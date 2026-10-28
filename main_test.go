package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/opencontainers/go-digest"
	"github.com/opencontainers/image-spec/specs-go"
	ociv1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// Invoke the real main in a subprocess so flags, stdout, exit codes and files
// are exercised without sharing CLI globals or working directories with tests.
// The subprocess also inherits race instrumentation from go test -race.
func TestCLIProcess(t *testing.T) {
	if os.Getenv("OCI_TOOL_E2E_PROCESS") != "1" {
		return
	}
	// Trust only the local fixture, including on platforms with native root
	// stores that do not honor SSL_CERT_FILE.
	cert, err := os.ReadFile(os.Getenv("OCI_TOOL_E2E_CA"))
	if err != nil {
		t.Fatal(err)
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(cert) {
		t.Fatal("invalid registry certificate")
	}
	x509.SetFallbackRoots(roots)
	for i, arg := range os.Args {
		if arg == "--" {
			os.Args = append([]string{"oci-tool"}, os.Args[i+1:]...)
			main()
			os.Exit(0)
		}
	}
	t.Fatal("missing CLI arguments")
}

type cliObject struct {
	data           []byte
	desc           ociv1.Descriptor
	noDigestHeader bool
}

func cliJSON(t *testing.T, value interface{}) []byte {
	t.Helper()
	data, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func cliContent(data []byte, mediaType string) cliObject {
	return cliObject{data: data, desc: ociv1.Descriptor{MediaType: mediaType, Digest: digest.FromBytes(data), Size: int64(len(data))}}
}

func cliLayer(t *testing.T, files map[string]string) (cliObject, digest.Digest) {
	t.Helper()
	var raw, compressed bytes.Buffer
	tw := tar.NewWriter(&raw)
	var names []string
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		data := []byte(files[name])
		if err := tw.WriteHeader(&tar.Header{Name: name, Mode: 0644, Size: int64(len(data))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(data); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	zw := gzip.NewWriter(&compressed)
	if _, err := zw.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return cliContent(compressed.Bytes(), ociv1.MediaTypeImageLayerGzip), digest.FromBytes(raw.Bytes())
}

type cliRegistry struct {
	host, configFile, certFile                                         string
	index, manifest, dockerIndex, dockerManifest, config, legacy, blob cliObject
	layers                                                             []cliObject
	rootFS                                                             ociv1.RootFS
}

func newCLIRegistry(t *testing.T) *cliRegistry {
	t.Helper()
	f := &cliRegistry{}
	base, baseDigest := cliLayer(t, map[string]string{"app/tool": "old executable\n", "app/metadata.jsonl": "{\"fixture\":true}\n"})
	top, topDigest := cliLayer(t, map[string]string{"app/tool": "current executable\n"})
	f.layers = []cliObject{base, top}
	f.rootFS = ociv1.RootFS{Type: "layers", DiffIDs: []digest.Digest{baseDigest, topDigest}}
	f.config = cliContent(cliJSON(t, map[string]interface{}{"architecture": "amd64", "os": "linux", "rootfs": f.rootFS}), ociv1.MediaTypeImageConfig)
	manifest := ociv1.Manifest{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ociv1.MediaTypeImageManifest, Config: f.config.desc, Layers: []ociv1.Descriptor{base.desc, top.desc}}
	f.manifest = cliContent(cliJSON(t, manifest), manifest.MediaType)
	desc := f.manifest.desc
	desc.Platform = &ociv1.Platform{OS: "linux", Architecture: "amd64"}
	index := ociv1.Index{Versioned: specs.Versioned{SchemaVersion: 2}, MediaType: ociv1.MediaTypeImageIndex, Manifests: []ociv1.Descriptor{desc}}
	f.index = cliContent(cliJSON(t, index), index.MediaType)
	manifest.MediaType = images.MediaTypeDockerSchema2Manifest
	manifest.Config.MediaType = images.MediaTypeDockerSchema2Config
	for i := range manifest.Layers {
		manifest.Layers[i].MediaType = images.MediaTypeDockerSchema2LayerGzip
	}
	f.dockerManifest = cliContent(cliJSON(t, manifest), manifest.MediaType)
	desc = f.dockerManifest.desc
	desc.Platform = &ociv1.Platform{OS: "linux", Architecture: "amd64"}
	index.MediaType = images.MediaTypeDockerSchema2ManifestList
	index.Manifests = []ociv1.Descriptor{desc}
	f.dockerIndex = cliContent(cliJSON(t, index), index.MediaType)
	if len(f.index.data) >= len(f.manifest.data) || len(f.dockerIndex.data) >= len(f.dockerManifest.data) {
		t.Fatal("fixture must reproduce an index smaller than its selected manifest")
	}
	payload := []byte(`{"schemaVersion":1,"name":"repo","tag":"legacy","architecture":"amd64","fsLayers":[],"history":[]}`)
	protected := cliJSON(t, map[string]interface{}{"formatLength": len(payload) - 1, "formatTail": base64.RawURLEncoding.EncodeToString([]byte("}"))})
	signed := append(append([]byte(nil), payload[:len(payload)-1]...), []byte(fmt.Sprintf(`,"signatures":[{"protected":%q}]}`, base64.RawURLEncoding.EncodeToString(protected)))...)
	f.legacy = cliContent(signed, images.MediaTypeDockerSchema1Manifest)
	f.legacy.desc.Digest = digest.FromBytes(payload)
	f.blob = cliContent(bytes.Repeat([]byte("x"), int(docker.MaxManifestSize)+1), "application/octet-stream")
	manifests := map[string]cliObject{"latest": f.index, "manifest": f.manifest, "docker-index": f.dockerIndex, "docker-manifest": f.dockerManifest, "legacy": f.legacy}
	for _, obj := range []cliObject{f.index, f.manifest, f.dockerIndex, f.dockerManifest, f.legacy} {
		manifests[obj.desc.Digest.String()] = obj
	}
	legacyNoHeader := f.legacy
	legacyNoHeader.noDigestHeader = true
	manifests["legacy-no-header"] = legacyNoHeader
	legacyText := legacyNoHeader
	legacyText.desc.MediaType = "text/plain; charset=utf-8"
	manifests["legacy-text"] = legacyText
	blobs := map[string]cliObject{}
	for _, obj := range []cliObject{base, top, f.config, f.blob} {
		blobs[obj.desc.Digest.String()] = obj
	}
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			if err := r.ParseForm(); err != nil {
				t.Error(err)
			}
			if r.Form.Get("scope") != "repository:bearer:pull" {
				t.Errorf("unexpected token scope: %v", r.Form)
			}
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write([]byte(`{"token":"fixture-token","access_token":"fixture-token","expires_in":300}`))
			return
		}
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/v2/"), "/")
		if len(parts) != 3 {
			http.NotFound(w, r)
			return
		}
		repo, endpoint, key := parts[0], parts[1], parts[2]
		if repo == "basic" {
			user, password, ok := r.BasicAuth()
			if !ok || user != "fixture" || password != "password" {
				w.Header().Set("WWW-Authenticate", `Basic realm="fixture"`)
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		} else if repo == "bearer" {
			if r.Header.Get("Authorization") != "Bearer fixture-token" {
				w.Header().Set("WWW-Authenticate", fmt.Sprintf(`Bearer realm="https://%s/token",service="fixture",scope="repository:bearer:pull"`, r.Host))
				w.WriteHeader(http.StatusUnauthorized)
				return
			}
		} else if repo != "repo" {
			http.NotFound(w, r)
			return
		}
		var obj cliObject
		var ok bool
		// Keep the two endpoints distinct to detect incorrect manifest routing.
		switch endpoint {
		case "manifests":
			obj, ok = manifests[key]
		case "blobs":
			obj, ok = blobs[key]
		}
		if !ok {
			http.NotFound(w, r)
			return
		}
		w.Header().Set("Content-Type", obj.desc.MediaType)
		w.Header().Set("Content-Length", fmt.Sprint(len(obj.data)))
		if !obj.noDigestHeader {
			w.Header().Set("Docker-Content-Digest", obj.desc.Digest.String())
		}
		if r.Method != http.MethodHead {
			_, _ = w.Write(obj.data)
		}
	}))
	t.Cleanup(srv.Close)
	f.host = strings.TrimPrefix(srv.URL, "https://")
	dir := t.TempDir()
	f.certFile = filepath.Join(dir, "registry.pem")
	if err := os.WriteFile(f.certFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw}), 0600); err != nil {
		t.Fatal(err)
	}
	f.configFile = filepath.Join(dir, "config.json")
	config := map[string]interface{}{"auths": map[string]interface{}{f.host: map[string]string{"auth": base64.StdEncoding.EncodeToString([]byte("fixture:password"))}}}
	if err := os.WriteFile(f.configFile, cliJSON(t, config), 0600); err != nil {
		t.Fatal(err)
	}
	return f
}

type cliCase struct {
	name   string
	args   []string
	stdin  []byte
	stdout []byte
	json   bool
	files  map[string][]byte
	exit   int
	stderr string
}

func runCLICases(t *testing.T, f *cliRegistry, cases []cliCase) {
	t.Helper()
	executable, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	slots := make(chan struct{}, 4)
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			slots <- struct{}{}
			defer func() { <-slots }()
			ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			args := append([]string{"-test.run=^TestCLIProcess$", "--", "--docker-config=" + f.configFile, "--timeout=5s"}, tc.args...)
			cmd := exec.CommandContext(ctx, executable, args...)
			cmd.Env = append(os.Environ(), "OCI_TOOL_E2E_PROCESS=1", "OCI_TOOL_E2E_CA="+f.certFile, "GODEBUG="+os.Getenv("GODEBUG")+",x509usefallbackroots=1")
			cmd.Dir = t.TempDir()
			cmd.Stdin = bytes.NewReader(tc.stdin)
			var stdout, stderr bytes.Buffer
			cmd.Stdout, cmd.Stderr = &stdout, &stderr
			err := cmd.Run()
			if ctx.Err() != nil {
				t.Fatalf("CLI timed out: %v\n%s", ctx.Err(), stderr.String())
			}
			exit := 0
			if err != nil {
				if e, ok := err.(*exec.ExitError); ok {
					exit = e.ExitCode()
				} else {
					t.Fatal(err)
				}
			}
			if exit != tc.exit {
				t.Fatalf("exit=%d, want %d\nstdout: %s\nstderr: %s", exit, tc.exit, stdout.String(), stderr.String())
			}
			if !strings.Contains(stderr.String(), tc.stderr) {
				t.Fatalf("stderr missing %q: %s", tc.stderr, stderr.String())
			}
			if tc.json {
				var got, want interface{}
				if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
					t.Fatalf("invalid JSON output: %v\n%s", err, stdout.String())
				}
				if err := json.Unmarshal(tc.stdout, &want); err != nil {
					t.Fatal(err)
				}
				if !reflect.DeepEqual(got, want) {
					t.Fatalf("JSON output: %s\nwant: %s", stdout.String(), tc.stdout)
				}
			} else if !bytes.Equal(stdout.Bytes(), tc.stdout) {
				t.Fatalf("stdout: %q\nwant: %q", stdout.Bytes(), tc.stdout)
			}
			for name, want := range tc.files {
				got, err := os.ReadFile(filepath.Join(cmd.Dir, name))
				if err != nil {
					t.Fatal(err)
				}
				if !bytes.Equal(got, want) {
					t.Fatalf("file %s: got %q, want %q", name, got, want)
				}
			}
			entries, err := os.ReadDir(cmd.Dir)
			if err != nil {
				t.Fatal(err)
			}
			if len(entries) != len(tc.files) {
				t.Fatalf("unexpected output files: %v", entries)
			}
		})
	}
}

func TestCLIRegistryCommands(t *testing.T) {
	f := newCLIRegistry(t)
	ref := f.host + "/repo:latest"
	legacyDescriptor := f.legacy.desc
	legacyDescriptor.MediaType = "application/octet-stream"
	cases := []cliCase{
		{name: "raw index", args: []string{"fetch", "raw", ref}, stdout: f.index.data},
		{name: "platform manifest", args: []string{"fetch", "manifest", "--platform=linux-amd64", ref}, stdout: f.manifest.data, json: true},
		{name: "image config", args: []string{"fetch", "image", "--platform=linux-amd64", ref}, stdout: f.config.data, json: true},
		{name: "resolve name", args: []string{"resolve", "name", ref}, stdout: []byte(ref + "@" + f.index.desc.Digest.String() + "\n")},
		{name: "resolve descriptor", args: []string{"resolve", "descriptor", ref}, stdout: cliJSON(t, f.index.desc), json: true},
		{name: "layer list", args: []string{"layer", "--platform=linux-amd64", "list", ref}, stdout: cliJSON(t, []ociv1.Descriptor{f.layers[0].desc, f.layers[1].desc}), json: true},
		{name: "unpacked layers", args: []string{"layer", "--platform=linux-amd64", "list", "--unpacked", ref}, stdout: cliJSON(t, f.rootFS), json: true},
		{name: "layer size", args: []string{"layer", "--platform=linux-amd64", "size", ref}, stdout: []byte(fmt.Sprintln(f.layers[0].desc.Size + f.layers[1].desc.Size))},
		{name: "layer download", args: []string{"fetch", "layer", "--quiet", "--platform=linux-amd64", "--position=first", ref}, files: map[string][]byte{f.layers[0].desc.Digest.Hex() + ".tar.gz": f.layers[0].data}},
		{name: "missing file", args: []string{"fetch", "file", "--quiet", "--platform=linux-amd64", ref, "app/absent"}, exit: 1, stderr: "file app/absent not found"},
		{name: "missing platform", args: []string{"fetch", "file", "--quiet", "--platform=linux-arm64", ref, "app/tool"}, exit: 1, stderr: "no manifest for platform linux-arm64 found"},
		{name: "manifest digest override", args: []string{"fetch", "--digest=" + f.manifest.desc.Digest.String(), "manifest", ref}, stdout: f.manifest.data, json: true},
		{name: "raw manifest digest", args: []string{"fetch", "--digest=" + f.manifest.desc.Digest.String(), "raw", ref}, stdout: f.manifest.data},
		{name: "raw config digest", args: []string{"fetch", "--digest=" + f.config.desc.Digest.String(), "raw", ref}, stdout: f.config.data},
		{name: "raw large blob", args: []string{"fetch", "--digest=" + f.blob.desc.Digest.String(), "raw", ref}, stdout: f.blob.data},
		{name: "file digest override", args: []string{"fetch", "--digest=" + f.manifest.desc.Digest.String(), "file", "--quiet", ref, "app/tool"}, files: map[string][]byte{"tool": []byte("current executable\n")}},
		{name: "custom output filename", args: []string{"fetch", "file", "--quiet", "--platform=linux-amd64", "--output=downloaded", ref, "app/tool"}, files: map[string][]byte{"downloaded": []byte("current executable\n")}},
		{name: "schema1 digest reference", args: []string{"fetch", "raw", f.host + "/repo@" + f.legacy.desc.Digest.String()}, stdout: f.legacy.data},
		{name: "schema1 digest override", args: []string{"fetch", "--digest=" + f.legacy.desc.Digest.String(), "raw", ref}, stdout: f.legacy.data},
		{name: "media type overrides stdin", args: []string{"fetch", "--descriptor-from-stdin", "--media-type=" + f.legacy.desc.MediaType, "raw", ref}, stdin: cliJSON(t, legacyDescriptor), stdout: f.legacy.data},
		{name: "stdin descriptor", args: []string{"fetch", "--descriptor-from-stdin", "raw", ref}, stdin: cliJSON(t, f.config.desc), stdout: f.config.data},
		{name: "digest overrides stdin", args: []string{"fetch", "--descriptor-from-stdin", "--digest=" + f.manifest.desc.Digest.String(), "raw", ref}, stdin: cliJSON(t, f.config.desc), stdout: f.manifest.data},
	}
	for _, tag := range []string{"latest", "manifest", "docker-index", "docker-manifest"} {
		for _, repo := range []string{"repo", "basic", "bearer"} {
			platform := []string{}
			if tag == "latest" || tag == "docker-index" {
				platform = append(platform, "--platform=linux-amd64")
			}
			for _, file := range []struct{ path, content string }{{"app/tool", "current executable\n"}, {"app/metadata.jsonl", "{\"fixture\":true}\n"}} {
				args := append([]string{"fetch", "file", "--quiet"}, platform...)
				args = append(args, f.host+"/"+repo+":"+tag, file.path)
				cases = append(cases, cliCase{name: "file/" + repo + "/" + tag + "/" + filepath.Base(file.path), args: args, files: map[string][]byte{filepath.Base(file.path): []byte(file.content)}})
			}
		}
	}
	for _, tag := range []string{"legacy", "legacy-no-header", "legacy-text"} {
		for _, repo := range []string{"repo", "basic", "bearer"} {
			legacyRef := f.host + "/" + repo + ":" + tag
			cases = append(cases,
				cliCase{name: "schema1/" + repo + "/" + tag + "/resolve", args: []string{"resolve", "descriptor", legacyRef}, stdout: cliJSON(t, f.legacy.desc), json: true},
				cliCase{name: "schema1/" + repo + "/" + tag + "/raw", args: []string{"fetch", "raw", legacyRef}, stdout: f.legacy.data},
			)
		}
	}
	runCLICases(t, f, cases)
}
