package commands

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
	"net/url"
	"path"
	"strings"

	"github.com/containerd/containerd/v2/core/images"
	"github.com/containerd/containerd/v2/core/remotes"
	"github.com/containerd/containerd/v2/core/remotes/docker"
	"github.com/containerd/containerd/v2/pkg/reference"
	"github.com/containerd/errdefs"
	"github.com/opencontainers/go-digest"
	ociv1 "github.com/opencontainers/image-spec/specs-go/v1"
)

// registryResolver preserves schema-1 resolution and raw downloads. It does not
// convert schema-1 images or add support for extracting their files or layers.
type registryResolver struct {
	remotes.Resolver
	hosts docker.RegistryHosts
}

func newRegistryResolver(hosts docker.RegistryHosts) remotes.Resolver {
	return &registryResolver{Resolver: docker.NewResolver(docker.ResolverOptions{Hosts: hosts}), hosts: hosts}
}

func (r *registryResolver) Resolve(ctx context.Context, ref string) (string, ociv1.Descriptor, error) {
	name, desc, err := r.Resolver.Resolve(ctx, ref)
	if !errors.Is(err, errdefs.ErrNotImplemented) {
		return name, desc, err
	}
	// v2 rejects schema-1 only when it needs to compute the manifest digest.
	// Retain v2's normal path when the registry supplies that digest in headers.
	spec, parseErr := reference.Parse(ref)
	if parseErr != nil {
		return "", ociv1.Descriptor{}, parseErr
	}
	ctx, parseErr = docker.ContextWithRepositoryScope(ctx, spec, false)
	if parseErr != nil {
		return "", ociv1.Descriptor{}, parseErr
	}
	hosts, hostErr := r.hosts(spec.Hostname())
	if hostErr != nil {
		return "", ociv1.Descriptor{}, hostErr
	}
	for _, host := range hosts {
		if !host.Capabilities.Has(docker.HostCapabilityPull | docker.HostCapabilityResolve) {
			continue
		}
		desc, err = resolveSchema1(ctx, host, spec)
		if err == nil {
			return spec.String(), desc, nil
		}
	}
	return "", ociv1.Descriptor{}, err
}

func resolveSchema1(ctx context.Context, host docker.RegistryHost, spec reference.Spec) (ociv1.Descriptor, error) {
	repo := strings.TrimPrefix(spec.Locator, spec.Hostname()+"/")
	u := url.URL{Scheme: host.Scheme, Host: host.Host, Path: path.Join(host.Path, repo, "manifests", spec.Object)}
	if host.Host != spec.Hostname() && !(spec.Hostname() == "docker.io" && host.Host == "registry-1.docker.io") {
		q := u.Query()
		q.Set("ns", spec.Hostname())
		u.RawQuery = q.Encode()
	}
	for attempt := 0; attempt < 3; attempt++ {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
		if err != nil {
			return ociv1.Descriptor{}, err
		}
		req.Header = host.Header.Clone()
		if req.Header == nil {
			req.Header = make(http.Header)
		}
		req.Header.Set("Accept", images.MediaTypeDockerSchema1Manifest)
		if host.Authorizer != nil {
			if err := host.Authorizer.Authorize(ctx, req); err != nil {
				return ociv1.Descriptor{}, err
			}
		}
		resp, err := host.Client.Do(req)
		if err != nil {
			return ociv1.Descriptor{}, err
		}
		if resp.StatusCode == http.StatusUnauthorized && host.Authorizer != nil {
			err = host.Authorizer.AddResponses(ctx, []*http.Response{resp})
			resp.Body.Close()
			if err != nil {
				return ociv1.Descriptor{}, err
			}
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			return ociv1.Descriptor{}, fmt.Errorf("schema-1 resolution: unexpected status %s", resp.Status)
		}
		mediaType, _, err := mime.ParseMediaType(resp.Header.Get("Content-Type"))
		if err != nil || (mediaType != images.MediaTypeDockerSchema1Manifest && mediaType != "text/plain") {
			return ociv1.Descriptor{}, fmt.Errorf("schema-1 resolution: unexpected content type %q", mediaType)
		}
		data, err := io.ReadAll(io.LimitReader(resp.Body, docker.MaxManifestSize+1))
		if err != nil {
			return ociv1.Descriptor{}, err
		}
		if int64(len(data)) > docker.MaxManifestSize {
			return ociv1.Descriptor{}, fmt.Errorf("schema-1 manifest exceeds %d bytes", docker.MaxManifestSize)
		}
		dgst, err := schema1Digest(data)
		if err != nil {
			return ociv1.Descriptor{}, fmt.Errorf("schema-1 manifest: %w", err)
		}
		return ociv1.Descriptor{MediaType: images.MediaTypeDockerSchema1Manifest, Digest: dgst, Size: int64(len(data))}, nil
	}
	return ociv1.Descriptor{}, fmt.Errorf("schema-1 resolution: authorization retries exhausted")
}

// schema1Digest hashes the original JSON payload, excluding the pretty-JWS
// envelope. This reconstructs the payload for addressing; it does not verify a
// signature or establish trust in the image.
func schema1Digest(data []byte) (digest.Digest, error) {
	var envelope struct {
		SchemaVersion int `json:"schemaVersion"`
		Signatures    []struct {
			Protected string `json:"protected"`
		} `json:"signatures"`
	}
	if err := json.Unmarshal(data, &envelope); err != nil {
		return "", err
	}
	if envelope.SchemaVersion != 1 || len(envelope.Signatures) == 0 {
		return "", errors.New("expected signed schema-1 manifest")
	}
	decode := func(s string) ([]byte, error) {
		return base64.RawURLEncoding.DecodeString(strings.TrimRight(s, "="))
	}
	protected, err := decode(envelope.Signatures[0].Protected)
	if err != nil {
		return "", err
	}
	var format struct {
		Length int    `json:"formatLength"`
		Tail   string `json:"formatTail"`
	}
	if err := json.Unmarshal(protected, &format); err != nil {
		return "", err
	}
	if format.Length < 0 || format.Length > len(data) {
		return "", errors.New("invalid protected format length")
	}
	tail, err := decode(format.Tail)
	if err != nil {
		return "", err
	}
	payload := append(append([]byte(nil), data[:format.Length]...), tail...)
	if !json.Valid(payload) {
		return "", errors.New("invalid unsigned payload")
	}
	return digest.FromBytes(payload), nil
}

func (r *registryResolver) Fetcher(ctx context.Context, ref string) (remotes.Fetcher, error) {
	fetcher, err := r.Resolver.Fetcher(ctx, ref)
	if err != nil {
		return nil, err
	}
	return schema1Fetcher{fetcher}, nil
}

type schema1Fetcher struct{ remotes.Fetcher }

func (f schema1Fetcher) Fetch(ctx context.Context, desc ociv1.Descriptor) (io.ReadCloser, error) {
	if desc.MediaType == images.MediaTypeDockerSchema1Manifest {
		// FetchByDigest supports the manifests endpoint without requiring a
		// schema-2 media type, and retains the schema-1 Accept header.
		reader, _, err := f.FetchByDigest(ctx, desc.Digest, remotes.WithMediaType(desc.MediaType))
		return reader, err
	}
	return f.Fetcher.Fetch(ctx, desc)
}

func (f schema1Fetcher) FetchByDigest(ctx context.Context, dgst digest.Digest, opts ...remotes.FetchByDigestOpts) (io.ReadCloser, ociv1.Descriptor, error) {
	byDigest, ok := f.Fetcher.(remotes.FetcherByDigest)
	if !ok {
		return nil, ociv1.Descriptor{}, fmt.Errorf("fetch by digest: %w", errdefs.ErrNotImplemented)
	}
	return byDigest.FetchByDigest(ctx, dgst, opts...)
}
