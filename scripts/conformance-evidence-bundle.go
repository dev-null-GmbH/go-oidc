//go:build ignore

// conformance-evidence-bundle packages and verifies the exact GitHub Actions
// artifact archives retained for a governed release.
package main

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

const (
	manifestName            = "CONFORMANCE-MANIFEST.json"
	manifestSchemaVersion   = 1
	evidenceSchemaVersion   = 2
	maxEvidenceSize         = int64(16 << 20)
	maxArtifactCompressed   = int64(128 << 20)
	maxBundleCompressed     = int64(512 << 20)
	maxArchiveUncompressed  = int64(512 << 20)
	maxExportUncompressed   = int64(256 << 20)
	maxZipEntryUncompressed = int64(256 << 20)
	maxZipEntries           = 20_000
	canonicalFileMode       = 0o644
	tapeBlockSize           = int64(512)
	endOfArchiveBlockCount  = int64(2)
)

var (
	commitPattern    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	digestPattern    = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	expectedProfiles = []string{
		"fapi1-op-mtls",
		"fapi1-op-mtls-jarm",
		"fapi1-op-mtls-par",
		"fapi1-op-mtls-par-jarm",
		"fapi1-op-private-key",
		"fapi1-op-private-key-jarm",
		"fapi1-op-private-key-par",
		"fapi1-op-private-key-par-jarm",
		"fapi2-ms-op-jar",
		"fapi2-ms-op-jarm",
		"fapi2-sp-op-mtls-dpop",
		"fapi2-sp-op-mtls-mtls",
		"fapi2-sp-op-private-key-dpop",
		"fapi2-sp-op-private-key-mtls",
		"fapiciba",
		"federation",
		"oidc",
	}
	canonicalTime = time.Unix(0, 0).UTC()
)

type releaseEvidence struct {
	SchemaVersion int    `json:"schemaVersion"`
	Repository    string `json:"repository"`
	ReleaseCommit string `json:"releaseCommit"`
	Conformance   struct {
		AggregateCheck struct {
			Workflow struct {
				ID int64 `json:"id"`
			} `json:"workflow"`
		} `json:"aggregateCheck"`
		Profiles []profileEvidence `json:"profiles"`
	} `json:"conformance"`
}

type profileEvidence struct {
	Profile  string           `json:"profile"`
	Artifact artifactEvidence `json:"artifact"`
}

type artifactEvidence struct {
	ID          int64  `json:"id"`
	Name        string `json:"name"`
	SizeInBytes int64  `json:"sizeInBytes"`
	Digest      string `json:"digest"`
	Expired     bool   `json:"expired"`
	HeadSHA     string `json:"headSha"`
}

type bundleManifest struct {
	SchemaVersion    int              `json:"schemaVersion"`
	Repository       string           `json:"repository"`
	ReleaseCommit    string           `json:"releaseCommit"`
	ConformanceRunID int64            `json:"conformanceRunId"`
	Artifacts        []bundleArtifact `json:"artifacts"`
}

type bundleArtifact struct {
	Profile      string `json:"profile"`
	ArtifactID   int64  `json:"artifactId"`
	ArtifactName string `json:"artifactName"`
	SizeInBytes  int64  `json:"sizeInBytes"`
	SHA256       string `json:"sha256"`
	BundlePath   string `json:"bundlePath"`
}

func main() {
	mode := flag.String("mode", "", "operation: pack or verify")
	evidencePath := flag.String("evidence", "", "release evidence JSON")
	archivesDir := flag.String("archives-dir", "", "directory containing <artifact-id>.zip archives")
	bundlePath := flag.String("bundle", "", "conformance evidence tar path")
	flag.Parse()

	if *evidencePath == "" || *bundlePath == "" {
		fatalf("-evidence and -bundle are required")
	}
	evidence, err := loadEvidence(*evidencePath)
	if err != nil {
		fatalf("load release evidence: %v", err)
	}
	manifest, manifestBytes, err := makeManifest(evidence)
	if err != nil {
		fatalf("prepare conformance manifest: %v", err)
	}

	switch *mode {
	case "pack":
		if *archivesDir == "" {
			fatalf("-archives-dir is required in pack mode")
		}
		if err := packBundle(*archivesDir, *bundlePath, manifest, manifestBytes); err != nil {
			fatalf("pack conformance evidence: %v", err)
		}
		fmt.Printf("Packed exact conformance evidence for %d profiles into %s\n", len(manifest.Artifacts), *bundlePath)
	case "verify":
		if *archivesDir != "" {
			fatalf("-archives-dir is not accepted in verify mode")
		}
		if err := verifyBundle(*bundlePath, manifest, manifestBytes); err != nil {
			fatalf("verify conformance evidence: %v", err)
		}
		fmt.Printf("Verified exact conformance evidence for %d profiles in %s\n", len(manifest.Artifacts), *bundlePath)
	default:
		fatalf("-mode must be pack or verify")
	}
}

func loadEvidence(filename string) (releaseEvidence, error) {
	linkInfo, err := os.Lstat(filename)
	if err != nil {
		return releaseEvidence{}, err
	}
	if !linkInfo.Mode().IsRegular() || linkInfo.Size() <= 0 || linkInfo.Size() > maxEvidenceSize {
		return releaseEvidence{}, fmt.Errorf("release evidence must be a non-empty, non-symlink regular file no larger than 16 MiB")
	}
	file, err := os.Open(filename)
	if err != nil {
		return releaseEvidence{}, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return releaseEvidence{}, err
	}
	if !info.Mode().IsRegular() || !os.SameFile(linkInfo, info) || info.Size() != linkInfo.Size() {
		return releaseEvidence{}, fmt.Errorf("release evidence changed before it could be read")
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxEvidenceSize+1))
	if err != nil {
		return releaseEvidence{}, err
	}
	if int64(len(contents)) != info.Size() || int64(len(contents)) > maxEvidenceSize {
		return releaseEvidence{}, errors.New("release evidence changed while reading or exceeds 16 MiB")
	}

	decoder := json.NewDecoder(bytes.NewReader(contents))
	var evidence releaseEvidence
	if err := decoder.Decode(&evidence); err != nil {
		return releaseEvidence{}, err
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return releaseEvidence{}, err
	}
	return evidence, nil
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var trailing any
	err := decoder.Decode(&trailing)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("JSON contains multiple top-level values")
	}
	return err
}

func makeManifest(evidence releaseEvidence) (bundleManifest, []byte, error) {
	if evidence.SchemaVersion != evidenceSchemaVersion || evidence.Repository != "dev-null-GmbH/go-oidc" || !commitPattern.MatchString(evidence.ReleaseCommit) {
		return bundleManifest{}, nil, errors.New("release evidence identity is invalid")
	}
	runID := evidence.Conformance.AggregateCheck.Workflow.ID
	if runID <= 0 {
		return bundleManifest{}, nil, errors.New("conformance run ID is invalid")
	}
	if len(evidence.Conformance.Profiles) != len(expectedProfiles) {
		return bundleManifest{}, nil, fmt.Errorf("expected %d conformance profiles, got %d", len(expectedProfiles), len(evidence.Conformance.Profiles))
	}

	profiles := append([]profileEvidence(nil), evidence.Conformance.Profiles...)
	sort.Slice(profiles, func(i, j int) bool { return profiles[i].Profile < profiles[j].Profile })
	manifest := bundleManifest{
		SchemaVersion:    manifestSchemaVersion,
		Repository:       evidence.Repository,
		ReleaseCommit:    evidence.ReleaseCommit,
		ConformanceRunID: runID,
		Artifacts:        make([]bundleArtifact, 0, len(profiles)),
	}
	seenIDs := make(map[int64]struct{}, len(profiles))
	var aggregateSize int64
	for index, profile := range profiles {
		if profile.Profile != expectedProfiles[index] {
			return bundleManifest{}, nil, fmt.Errorf("unexpected or duplicate conformance profile %q", profile.Profile)
		}
		artifact := profile.Artifact
		expectedName := fmt.Sprintf("conformance-%s-%d", profile.Profile, runID)
		if artifact.ID <= 0 || artifact.Name != expectedName || artifact.SizeInBytes <= 0 || !digestPattern.MatchString(artifact.Digest) || artifact.Expired || artifact.HeadSHA != evidence.ReleaseCommit {
			return bundleManifest{}, nil, fmt.Errorf("artifact evidence is invalid for profile %s", profile.Profile)
		}
		if artifact.SizeInBytes > maxArtifactCompressed {
			return bundleManifest{}, nil, fmt.Errorf("artifact %s exceeds the 128 MiB compressed size limit", profile.Profile)
		}
		aggregateSize += artifact.SizeInBytes
		if aggregateSize > maxBundleCompressed {
			return bundleManifest{}, nil, errors.New("conformance artifacts exceed the 512 MiB aggregate compressed size limit")
		}
		if _, duplicate := seenIDs[artifact.ID]; duplicate {
			return bundleManifest{}, nil, fmt.Errorf("duplicate artifact ID %d", artifact.ID)
		}
		seenIDs[artifact.ID] = struct{}{}
		manifest.Artifacts = append(manifest.Artifacts, bundleArtifact{
			Profile:      profile.Profile,
			ArtifactID:   artifact.ID,
			ArtifactName: artifact.Name,
			SizeInBytes:  artifact.SizeInBytes,
			SHA256:       strings.TrimPrefix(artifact.Digest, "sha256:"),
			BundlePath:   "artifacts/" + profile.Profile + ".zip",
		})
	}

	encoded, err := json.MarshalIndent(manifest, "", "  ")
	if err != nil {
		return bundleManifest{}, nil, err
	}
	encoded = append(encoded, '\n')
	return manifest, encoded, nil
}

func packBundle(archivesDir, output string, manifest bundleManifest, manifestBytes []byte) error {
	if err := validateArchiveDirectory(archivesDir, manifest.Artifacts); err != nil {
		return err
	}
	if _, err := os.Lstat(output); err == nil {
		return fmt.Errorf("bundle output already exists: %s", output)
	} else if !errors.Is(err, os.ErrNotExist) {
		return err
	}
	outputDir := filepath.Dir(output)
	if err := os.MkdirAll(outputDir, 0o755); err != nil {
		return err
	}
	temporary, err := os.CreateTemp(outputDir, ".conformance-evidence-*.tar")
	if err != nil {
		return err
	}
	temporaryName := temporary.Name()
	committed := false
	defer func() {
		_ = temporary.Close()
		if !committed {
			_ = os.Remove(temporaryName)
		}
	}()

	tw := tar.NewWriter(temporary)
	if err := writeTarFile(tw, manifestName, manifestBytes); err != nil {
		return err
	}
	for _, artifact := range manifest.Artifacts {
		filename := filepath.Join(archivesDir, fmt.Sprintf("%d.zip", artifact.ArtifactID))
		contents, err := readExactArchive(filename, artifact.SizeInBytes)
		if err != nil {
			return err
		}
		if err := validateArtifactBytes(contents, artifact); err != nil {
			return err
		}
		if err := writeTarFile(tw, artifact.BundlePath, contents); err != nil {
			return err
		}
	}
	if err := tw.Close(); err != nil {
		return err
	}
	if err := temporary.Sync(); err != nil {
		return err
	}
	if err := temporary.Close(); err != nil {
		return err
	}
	if err := os.Chmod(temporaryName, 0o644); err != nil {
		return err
	}
	if err := os.Rename(temporaryName, output); err != nil {
		return err
	}
	committed = true
	return nil
}

func validateArchiveDirectory(directory string, artifacts []bundleArtifact) error {
	entries, err := os.ReadDir(directory)
	if err != nil {
		return err
	}
	expected := make(map[string]int64, len(artifacts))
	for _, artifact := range artifacts {
		expected[fmt.Sprintf("%d.zip", artifact.ArtifactID)] = artifact.SizeInBytes
	}
	if len(entries) != len(expected) {
		return fmt.Errorf("archive directory contains %d entries, expected %d", len(entries), len(expected))
	}
	for _, entry := range entries {
		expectedSize, ok := expected[entry.Name()]
		if !ok {
			return fmt.Errorf("unexpected archive directory entry %q", entry.Name())
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		if !info.Mode().IsRegular() {
			return fmt.Errorf("archive input is not a regular file: %s", entry.Name())
		}
		if info.Size() != expectedSize || info.Size() > maxArtifactCompressed {
			return fmt.Errorf("archive input size is invalid for %s", entry.Name())
		}
	}
	return nil
}

func readExactArchive(filename string, expectedSize int64) ([]byte, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() || expectedSize <= 0 || expectedSize > maxArtifactCompressed || info.Size() != expectedSize {
		return nil, fmt.Errorf("archive file size or type is invalid: %s", filename)
	}
	contents, err := io.ReadAll(io.LimitReader(file, maxArtifactCompressed+1))
	if err != nil {
		return nil, err
	}
	if int64(len(contents)) != expectedSize {
		return nil, fmt.Errorf("archive changed while reading: %s", filename)
	}
	return contents, nil
}

func writeTarFile(writer *tar.Writer, name string, contents []byte) error {
	header := &tar.Header{
		Name:     name,
		Mode:     canonicalFileMode,
		Size:     int64(len(contents)),
		ModTime:  canonicalTime,
		Typeflag: tar.TypeReg,
		Format:   tar.FormatUSTAR,
	}
	if err := writer.WriteHeader(header); err != nil {
		return err
	}
	_, err := writer.Write(contents)
	return err
}

func verifyBundle(filename string, manifest bundleManifest, manifestBytes []byte) error {
	info, err := os.Lstat(filename)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() {
		return errors.New("bundle is not a regular file")
	}
	expectedSize := tarEntrySize(int64(len(manifestBytes))) + endOfArchiveBlockCount*tapeBlockSize
	for _, artifact := range manifest.Artifacts {
		expectedSize += tarEntrySize(artifact.SizeInBytes)
	}
	if info.Size() != expectedSize {
		return fmt.Errorf("bundle size is %d, expected deterministic size %d", info.Size(), expectedSize)
	}

	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()
	reader := tar.NewReader(file)
	if err := verifyTarEntry(reader, manifestName, manifestBytes, nil); err != nil {
		return err
	}
	for _, artifact := range manifest.Artifacts {
		artifact := artifact
		if err := verifyTarEntry(reader, artifact.BundlePath, nil, &artifact); err != nil {
			return err
		}
	}
	if header, err := reader.Next(); err != io.EOF {
		if err != nil {
			return err
		}
		return fmt.Errorf("unexpected bundle member %q", header.Name)
	}
	return nil
}

func verifyTarEntry(reader *tar.Reader, expectedName string, expectedBytes []byte, artifact *bundleArtifact) error {
	header, err := reader.Next()
	if err != nil {
		return err
	}
	if header.Name != expectedName || header.Typeflag != tar.TypeReg || header.Mode != canonicalFileMode || header.Uid != 0 || header.Gid != 0 || header.Uname != "" || header.Gname != "" || !header.ModTime.Equal(canonicalTime) || header.Format != tar.FormatUSTAR {
		return fmt.Errorf("bundle member header is not canonical for %s", expectedName)
	}
	contents, err := io.ReadAll(reader)
	if err != nil {
		return err
	}
	if int64(len(contents)) != header.Size {
		return fmt.Errorf("bundle member size mismatch for %s", expectedName)
	}
	if artifact == nil {
		if !bytes.Equal(contents, expectedBytes) {
			return errors.New("internal conformance manifest does not match release evidence")
		}
		return nil
	}
	return validateArtifactBytes(contents, *artifact)
}

func tarEntrySize(contentSize int64) int64 {
	return tapeBlockSize + ((contentSize+tapeBlockSize-1)/tapeBlockSize)*tapeBlockSize
}

func validateArtifactBytes(contents []byte, artifact bundleArtifact) error {
	if int64(len(contents)) != artifact.SizeInBytes {
		return fmt.Errorf("artifact %s has size %d, expected %d", artifact.Profile, len(contents), artifact.SizeInBytes)
	}
	digest := sha256.Sum256(contents)
	actualDigest := hex.EncodeToString(digest[:])
	if actualDigest != artifact.SHA256 {
		return fmt.Errorf("artifact %s has SHA-256 %s, expected %s", artifact.Profile, actualDigest, artifact.SHA256)
	}
	if err := validateActionsArchive(contents); err != nil {
		return fmt.Errorf("artifact %s is invalid: %w", artifact.Profile, err)
	}
	return nil
}

func validateActionsArchive(contents []byte) error {
	reader, err := zip.NewReader(bytes.NewReader(contents), int64(len(contents)))
	if err != nil {
		return err
	}
	if len(reader.File) == 0 || len(reader.File) > maxZipEntries {
		return fmt.Errorf("artifact ZIP contains %d entries", len(reader.File))
	}
	seen := make(map[string]struct{}, len(reader.File))
	hasServerLog := false
	exportCount := 0
	var total int64
	for _, file := range reader.File {
		if err := validateZipPath(file.Name); err != nil {
			return err
		}
		if _, duplicate := seen[file.Name]; duplicate {
			return fmt.Errorf("duplicate ZIP member %q", file.Name)
		}
		seen[file.Name] = struct{}{}
		mode := file.Mode()
		if file.FileInfo().IsDir() {
			if !mode.IsDir() {
				return fmt.Errorf("ZIP member %q has inconsistent directory mode", file.Name)
			}
			continue
		}
		if !mode.IsRegular() {
			return fmt.Errorf("ZIP member %q is not a regular file or directory", file.Name)
		}
		if file.UncompressedSize64 > uint64(maxZipEntryUncompressed) {
			return fmt.Errorf("ZIP member %q exceeds the uncompressed limit", file.Name)
		}
		total += int64(file.UncompressedSize64)
		if total > maxArchiveUncompressed {
			return errors.New("artifact ZIP exceeds the total uncompressed limit")
		}
		entryBytes, err := readZipEntry(file, maxZipEntryUncompressed)
		if err != nil {
			return err
		}
		if path.Base(file.Name) == "auth-server.log" {
			if len(entryBytes) == 0 {
				return fmt.Errorf("authorization-server log %q is empty", file.Name)
			}
			hasServerLog = true
		}
		if strings.HasSuffix(strings.ToLower(file.Name), ".zip") {
			if err := validateExportArchive(entryBytes); err != nil {
				return fmt.Errorf("export %q is invalid: %w", file.Name, err)
			}
			exportCount++
		}
	}
	if !hasServerLog || exportCount == 0 {
		return fmt.Errorf("artifact ZIP must contain auth-server.log and at least one signed export ZIP")
	}
	return nil
}

func validateExportArchive(contents []byte) error {
	reader, err := zip.NewReader(bytes.NewReader(contents), int64(len(contents)))
	if err != nil {
		return err
	}
	if len(reader.File) == 0 || len(reader.File) > maxZipEntries {
		return fmt.Errorf("export ZIP contains %d entries", len(reader.File))
	}
	seen := make(map[string]struct{}, len(reader.File))
	jsonMembers := make(map[string]string)
	signatureMembers := make(map[string]string)
	var total int64
	for _, file := range reader.File {
		if err := validateZipPath(file.Name); err != nil {
			return err
		}
		if _, duplicate := seen[file.Name]; duplicate {
			return fmt.Errorf("duplicate export member %q", file.Name)
		}
		seen[file.Name] = struct{}{}
		mode := file.Mode()
		if file.FileInfo().IsDir() {
			if !mode.IsDir() {
				return fmt.Errorf("export member %q has inconsistent directory mode", file.Name)
			}
			continue
		}
		if !mode.IsRegular() {
			return fmt.Errorf("export member %q is not a regular file or directory", file.Name)
		}
		if file.UncompressedSize64 > uint64(maxZipEntryUncompressed) {
			return fmt.Errorf("export member %q exceeds the uncompressed limit", file.Name)
		}
		total += int64(file.UncompressedSize64)
		if total > maxExportUncompressed {
			return errors.New("export ZIP exceeds the total uncompressed limit")
		}
		entryBytes, err := readZipEntry(file, maxZipEntryUncompressed)
		if err != nil {
			return err
		}
		extension := path.Ext(file.Name)
		stem := strings.TrimSuffix(file.Name, extension)
		switch strings.ToLower(extension) {
		case ".json":
			if len(entryBytes) == 0 {
				return fmt.Errorf("export JSON member %q is empty", file.Name)
			}
			if previous, duplicate := jsonMembers[stem]; duplicate {
				return fmt.Errorf("export JSON members %q and %q have the same path stem", previous, file.Name)
			}
			jsonMembers[stem] = file.Name
		case ".sig":
			if len(entryBytes) == 0 {
				return fmt.Errorf("export signature member %q is empty", file.Name)
			}
			if previous, duplicate := signatureMembers[stem]; duplicate {
				return fmt.Errorf("export signature members %q and %q have the same path stem", previous, file.Name)
			}
			signatureMembers[stem] = file.Name
		}
	}
	if len(jsonMembers) == 0 {
		return errors.New("export ZIP contains no non-empty JSON logs")
	}
	for stem, member := range jsonMembers {
		if _, found := signatureMembers[stem]; !found {
			return fmt.Errorf("export JSON member %q has no sibling signature", member)
		}
	}
	for stem, member := range signatureMembers {
		if _, found := jsonMembers[stem]; !found {
			return fmt.Errorf("export signature member %q has no sibling JSON log", member)
		}
	}
	return nil
}

func readZipEntry(file *zip.File, limit int64) ([]byte, error) {
	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	contents, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(contents)) > limit {
		return nil, fmt.Errorf("ZIP member %q exceeds the read limit", file.Name)
	}
	return contents, nil
}

func validateZipPath(name string) error {
	if name == "" || strings.Contains(name, `\`) || strings.HasPrefix(name, "/") || path.Clean(name) != name || name == "." || name == ".." || strings.HasPrefix(name, "../") {
		return fmt.Errorf("unsafe ZIP member path %q", name)
	}
	return nil
}

func fatalf(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
	os.Exit(1)
}
