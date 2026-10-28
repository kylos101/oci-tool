package commands

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/opencontainers/go-digest"
	ociv1 "github.com/opencontainers/image-spec/specs-go/v1"
)

type registryObject struct {
	data      []byte
	mediaType string
	digest    digest.Digest
}

func object(data []byte, mediaType string) registryObject {
	return registryObject{data, mediaType, digest.FromBytes(data)}
}

// The fixture deliberately separates manifests/ and blobs/. Accepting either
// endpoint would hide schema-1 downloads incorrectly routed as blobs by v2.
func testRegistry(t *testing.T, manifests, blobs map[string]registryObject, digestHeader bool, auth string) (remotes.Resolver, string) {
	t.Helper()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" && strings.HasPrefix(auth, "Bearer ") {
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("scope") != "repository:repo:pull" {
				t.Errorf("wrong token scope: %s", r.Form)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = fmt.Fprintf(w, `{"token":%q,"access_token":%q,"expires_in":300}`, strings.TrimPrefix(auth, "Bearer "), strings.TrimPrefix(auth, "Bearer "))
			return
		}
		if auth != "" && r.Header.Get("Authorization") != auth {
			if strings.HasPrefix(auth, "Bearer ") {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="https://%s/token",service="registry",scope="repository:repo:pull"`, r.Host))
			} else {
				w.Header().Set("WWW-Authenticate", `Basic realm="registry"`)
			}
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var obj registryObject
		var ok bool
		switch {
		case strings.HasPrefix(r.URL.Path, "/v2/repo/manifests/"):
			obj, ok = manifests[strings.TrimPrefix(r.URL.Path, "/v2/repo/manifests/")]
		case strings.HasPrefix(r.URL.Path, "/v2/repo/blobs/"):
			obj, ok = blobs[strings.TrimPrefix(r.URL.Path, "/v2/repo/blobs/")]
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", obj.mediaType)
		w.Header().Set("Content-Length", fmt.Sprint(len(obj.data)))
		if digestHeader {
			w.Header().Set("Docker-Content-Digest", obj.digest.String())
		}
		if r.Method != http.MethodHead {
			_, _ = w.Write(obj.data)
		}
	}))
	t.Cleanup(srv.Close)
	authorizer := docker.NewDockerAuthorizer(docker.WithAuthClient(srv.Client()), docker.WithAuthCreds(func(string) (string, string, error) {
		return "user", "password", nil
	}))
	hosts := docker.ConfigureDefaultRegistries(docker.WithClient(srv.Client()), docker.WithAuthorizer(authorizer))
	return newRegistryResolver(hosts), strings.TrimPrefix(srv.URL, "https://") + "/repo:latest"
}

func readObject(t *testing.T, res remotes.Resolver, name string, desc ociv1.Descriptor) []byte {
	t.Helper()
	fetcher, err := res.Fetcher(context.Background(), name)
	if err != nil {
		t.Fatal(err)
	}
	r, err := fetcher.Fetch(context.Background(), desc)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	data, err := io.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestDigestOverridesResolveTargetMetadata(t *testing.T) {
	config := object([]byte(`{"architecture":"amd64","os":"linux"}`), ociv1.MediaTypeImageConfig)
	manifest := object([]byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"config":{"mediaType":%q,"digest":%q,"size":%d},"layers":[],"annotations":{"padding":%q}}`, ociv1.MediaTypeImageManifest, config.mediaType, config.digest, len(config.data), strings.Repeat("x", 500))), ociv1.MediaTypeImageManifest)
	index := object([]byte(fmt.Sprintf(`{"schemaVersion":2,"mediaType":%q,"manifests":[{"mediaType":%q,"digest":%q,"size":%d,"platform":{"os":"linux","architecture":"amd64"}}]}`, ociv1.MediaTypeImageIndex, manifest.mediaType, manifest.digest, len(manifest.data))), ociv1.MediaTypeImageIndex)
	if len(index.data) >= len(manifest.data) {
		t.Fatal("fixture must have a manifest larger than its index")
	}
	res, ref := testRegistry(t, map[string]registryObject{"latest": index, index.digest.String(): index, manifest.digest.String(): manifest}, map[string]registryObject{config.digest.String(): config}, true, "")
	for _, target := range []registryObject{manifest, config} {
		t.Run(target.mediaType, func(t *testing.T) {
			name, desc, err := resolveDescriptor(context.Background(), res, ref, target.digest)
			if err != nil {
				t.Fatal(err)
			}
			if desc.Digest != target.digest || desc.Size != int64(len(target.data)) || desc.MediaType != target.mediaType {
				t.Fatalf("wrong target descriptor: %+v", desc)
			}
			if got := readObject(t, res, name, desc); !bytes.Equal(got, target.data) {
				t.Fatalf("incorrect raw content: %s", got)
			}
		})
	}
	// Exercise both manifest entry points that formerly reused the index size.
	for _, platform := range []bool{false, true} {
		var mf *ociv1.Manifest
		var err error
		if platform {
			_, mf, err = interactiveFetchManifestOrIndex(context.Background(), res, ref, "linux-amd64", "")
		} else {
			_, mf, err = fetchManifest(context.Background(), res, ref, manifest.digest)
		}
		if err != nil {
			t.Fatal(err)
		}
		if mf.Config.Digest != config.digest {
			t.Fatalf("wrong manifest: %+v", mf)
		}
	}
}

func signedSchema1(t *testing.T, lengthOverride *int) ([]byte, digest.Digest) {
	t.Helper()
	payload := []byte(`{"schemaVersion":1,"name":"repo","tag":"latest","architecture":"amd64","fsLayers":[],"history":[]}`)
	length := len(payload) - 1
	if lengthOverride != nil {
		length = *lengthOverride
	}
	format, err := json.Marshal(map[string]interface{}{"formatLength": length, "formatTail": base64.RawURLEncoding.EncodeToString([]byte("}"))})
	if err != nil {
		t.Fatal(err)
	}
	data := append(append([]byte(nil), payload[:len(payload)-1]...), []byte(fmt.Sprintf(`,"signatures":[{"protected":%q}]}`, base64.RawURLEncoding.EncodeToString(format)))...)
	return data, digest.FromBytes(payload)
}

func TestSchema1ResolutionAndRawFetch(t *testing.T) {
	data, dgst := signedSchema1(t, nil)
	for _, header := range []bool{false, true} {
		for _, auth := range []string{"", "Basic " + base64.StdEncoding.EncodeToString([]byte("user:password")), "Bearer testtoken"} {
			for _, mediaType := range []string{images.MediaTypeDockerSchema1Manifest, "text/plain; charset=utf-8"} {
				t.Run(fmt.Sprintf("digest-header=%v/auth=%s/%s", header, strings.Fields(auth + " anonymous")[0], mediaType), func(t *testing.T) {
					obj := registryObject{data, mediaType, dgst}
					res, ref := testRegistry(t, map[string]registryObject{"latest": obj, dgst.String(): obj}, nil, header, auth)
					for _, override := range []digest.Digest{"", dgst} {
						name, desc, err := resolveDescriptor(context.Background(), res, ref, override)
						if err != nil {
							t.Fatal(err)
						}
						if desc.Digest != dgst || desc.Size != int64(len(data)) || desc.MediaType != images.MediaTypeDockerSchema1Manifest {
							t.Fatalf("wrong schema-1 descriptor: %+v", desc)
						}
						if got := readObject(t, res, name, desc); !bytes.Equal(got, data) {
							t.Fatal("raw fetch changed the signed manifest")
						}
					}
				})
			}
		}
	}
}

func TestSchema1DigestRejectsMalformedEnvelope(t *testing.T) {
	negative, oversized := -1, 1000000
	badNegative, _ := signedSchema1(t, &negative)
	badOversized, _ := signedSchema1(t, &oversized)
	for _, data := range [][]byte{badNegative, badOversized, []byte(`{}`), []byte(`{"schemaVersion":1,"signatures":[{"protected":"!"}]}`), []byte(`{"schemaVersion":1,"signatures":[{"protected":"e30"}]}`)} {
		if _, err := schema1Digest(data); err == nil {
			t.Fatalf("accepted malformed envelope: %s", data)
		}
	}
}

func TestSchema1ResolutionRejectsInvalidManifests(t *testing.T) {
	for _, data := range [][]byte{
		[]byte(`{"schemaVersion":1,"signatures":[]}`),
		bytes.Repeat([]byte("x"), int(docker.MaxManifestSize)+1),
	} {
		obj := object(data, images.MediaTypeDockerSchema1Manifest)
		res, ref := testRegistry(t, map[string]registryObject{"latest": obj}, nil, false, "")
		if _, _, err := res.Resolve(context.Background(), ref); err == nil {
			t.Fatal("accepted invalid schema-1 manifest")
		}
	}
}

func TestRawDigestAndDescriptorOverrides(t *testing.T) {
	manifest := object([]byte(`{"schemaVersion":2}`), ociv1.MediaTypeImageManifest)
	largeBlob := object(bytes.Repeat([]byte("x"), int(docker.MaxManifestSize)+1), "application/octet-stream")
	signed, dgst := signedSchema1(t, nil)
	legacy := registryObject{signed, images.MediaTypeDockerSchema1Manifest, dgst}
	res, ref := testRegistry(t, map[string]registryObject{"latest": manifest, manifest.digest.String(): manifest, legacy.digest.String(): legacy}, map[string]registryObject{largeBlob.digest.String(): largeBlob}, true, "")
	for _, tc := range []struct {
		name      string
		digest    digest.Digest
		custom    ociv1.Descriptor
		mediaType string
		want      registryObject
	}{
		{name: "manifest by digest", digest: manifest.digest, want: manifest},
		{name: "blob beyond manifest size limit", digest: largeBlob.digest, want: largeBlob},
		{name: "schema-1 by digest", digest: legacy.digest, want: legacy},
		{name: "stdin descriptor", custom: ociv1.Descriptor{Digest: largeBlob.digest, Size: int64(len(largeBlob.data)), MediaType: largeBlob.mediaType}, want: largeBlob},
		{name: "digest overrides stdin", digest: largeBlob.digest, custom: ociv1.Descriptor{Digest: manifest.digest, Size: int64(len(manifest.data)), MediaType: manifest.mediaType}, want: largeBlob},
		{name: "media type overrides stdin", custom: ociv1.Descriptor{Digest: legacy.digest, Size: int64(len(legacy.data)), MediaType: "application/octet-stream"}, mediaType: legacy.mediaType, want: legacy},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r, err := fetchRaw(context.Background(), res, ref, tc.digest, tc.custom, tc.mediaType)
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			got, err := io.ReadAll(r)
			if err != nil {
				t.Fatal(err)
			}
			if !bytes.Equal(got, tc.want.data) {
				t.Fatal("wrong raw content")
			}
		})
	}
}
