//go:build ignore

// generate-release-sbom writes a deterministic SPDX 2.3 SBOM for every Go
// module shipped in the release source tree.
package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"
)

type goModule struct {
	Path    string
	Version string
	Main    bool
	Replace *goModule
	Dir     string
}

type moduleGraph struct {
	Root    string
	Modules []goModule
}

type creationInfo struct {
	Created  string   `json:"created"`
	Creators []string `json:"creators"`
}

type spdxPackage struct {
	Name               string `json:"name"`
	SPDXID             string `json:"SPDXID"`
	VersionInfo        string `json:"versionInfo"`
	DownloadLocation   string `json:"downloadLocation"`
	FilesAnalyzed      bool   `json:"filesAnalyzed"`
	LicenseConcluded   string `json:"licenseConcluded"`
	LicenseDeclared    string `json:"licenseDeclared"`
	CopyrightText      string `json:"copyrightText"`
	PrimaryPackageType string `json:"primaryPackagePurpose,omitempty"`
}

type relationship struct {
	SPDXElementID      string `json:"spdxElementId"`
	RelationshipType   string `json:"relationshipType"`
	RelatedSPDXElement string `json:"relatedSpdxElement"`
}

type document struct {
	SPDXVersion       string         `json:"spdxVersion"`
	DataLicense       string         `json:"dataLicense"`
	SPDXID            string         `json:"SPDXID"`
	Name              string         `json:"name"`
	DocumentNamespace string         `json:"documentNamespace"`
	DocumentComment   string         `json:"documentComment,omitempty"`
	CreationInfo      creationInfo   `json:"creationInfo"`
	Packages          []spdxPackage  `json:"packages"`
	Relationships     []relationship `json:"relationships"`
}

var (
	tagPattern    = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+-d0\.[1-9][0-9]*$`)
	commitPattern = regexp.MustCompile(`^[0-9a-f]{40}$`)
)

func main() {
	tag := flag.String("tag", "", "release tag")
	commit := flag.String("commit", "", "release commit")
	created := flag.String("created", "", "RFC 3339 creation time")
	output := flag.String("output", "", "output SPDX JSON path")
	flag.Parse()

	if !tagPattern.MatchString(*tag) {
		fatalf("invalid release tag %q", *tag)
	}
	if !commitPattern.MatchString(*commit) {
		fatalf("invalid release commit %q", *commit)
	}
	createdAt, err := time.Parse(time.RFC3339, *created)
	if err != nil {
		fatalf("parse creation time: %v", err)
	}
	if *output == "" {
		fatalf("output path is required")
	}

	repositoryRoot, err := filepath.Abs(".")
	if err != nil {
		fatalf("resolve repository root: %v", err)
	}
	moduleRoots, err := findModuleRoots(repositoryRoot)
	if err != nil {
		fatalf("find Go modules: %v", err)
	}
	graphs := make([]moduleGraph, 0, len(moduleRoots))
	for _, root := range moduleRoots {
		modules, err := listModules(root)
		if err != nil {
			fatalf("list Go modules in %s: %v", relativePath(repositoryRoot, root), err)
		}
		graphs = append(graphs, moduleGraph{Root: root, Modules: modules})
	}

	rootModulePath := ""
	for _, module := range graphs[0].Modules {
		if module.Main {
			rootModulePath = module.Path
			break
		}
	}
	if rootModulePath == "" {
		fatalf("root module graph has no main module")
	}

	packagesByID := make(map[string]spdxPackage)
	relationshipsByKey := make(map[string]relationship)
	mainPackageIDs := make(map[string]string)
	var replacementNotes []string

	for _, graph := range graphs {
		mainID := ""
		for _, module := range graph.Modules {
			if !module.Main {
				continue
			}
			if mainID != "" {
				fatalf("module graph %s contains multiple main modules", graph.Root)
			}
			mainID = spdxID(module.Path, *tag)
			mainPackageIDs[graph.Root] = mainID
			packagesByID[mainID] = newPackage(module.Path, *tag, "SOURCE")
		}
		if mainID == "" {
			fatalf("module graph %s has no main module", graph.Root)
		}

		for _, module := range graph.Modules {
			if module.Main {
				continue
			}

			dependencyPath := module.Path
			dependencyVersion := module.Version
			if module.Replace != nil {
				note, ok := validateReleaseRootReplacement(
					repositoryRoot, graph.Root, rootModulePath, *tag, module,
				)
				if !ok {
					fatalf(
						"module graph %s contains unapproved replacement for %s",
						relativePath(repositoryRoot, graph.Root), module.Path,
					)
				}
				replacementNotes = append(replacementNotes, note)
				dependencyVersion = *tag
			}
			if dependencyPath == "" || dependencyVersion == "" {
				fatalf(
					"module has incomplete identity: path=%q version=%q",
					dependencyPath, dependencyVersion,
				)
			}

			dependencyID := spdxID(dependencyPath, dependencyVersion)
			if _, exists := packagesByID[dependencyID]; !exists {
				purpose := "LIBRARY"
				if dependencyPath == rootModulePath && dependencyVersion == *tag {
					purpose = "SOURCE"
				}
				packagesByID[dependencyID] = newPackage(
					dependencyPath, dependencyVersion, purpose,
				)
			}
			addRelationship(relationshipsByKey, relationship{
				SPDXElementID:      mainID,
				RelationshipType:   "DEPENDS_ON",
				RelatedSPDXElement: dependencyID,
			})
		}
	}

	for _, mainID := range mainPackageIDs {
		addRelationship(relationshipsByKey, relationship{
			SPDXElementID:      "SPDXRef-DOCUMENT",
			RelationshipType:   "DESCRIBES",
			RelatedSPDXElement: mainID,
		})
	}

	packages := make([]spdxPackage, 0, len(packagesByID))
	for _, pkg := range packagesByID {
		packages = append(packages, pkg)
	}
	sort.Slice(packages, func(i, j int) bool {
		if packages[i].Name == packages[j].Name {
			return packages[i].VersionInfo < packages[j].VersionInfo
		}
		return packages[i].Name < packages[j].Name
	})

	relationships := make([]relationship, 0, len(relationshipsByKey))
	for _, item := range relationshipsByKey {
		relationships = append(relationships, item)
	}
	sort.Slice(relationships, func(i, j int) bool {
		left := relationships[i]
		right := relationships[j]
		if left.SPDXElementID != right.SPDXElementID {
			return left.SPDXElementID < right.SPDXElementID
		}
		if left.RelationshipType != right.RelationshipType {
			return left.RelationshipType < right.RelationshipType
		}
		return left.RelatedSPDXElement < right.RelatedSPDXElement
	})
	sort.Strings(replacementNotes)

	doc := document{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		Name:              "go-oidc-" + strings.TrimPrefix(*tag, "v"),
		DocumentNamespace: fmt.Sprintf("https://github.com/dev-null-GmbH/go-oidc/releases/%s/sbom/%s", *tag, *commit),
		DocumentComment: strings.Join(append(
			[]string{"Go module roots: " + strings.Join(relativePaths(repositoryRoot, moduleRoots), ", ")},
			replacementNotes...,
		), "; "),
		CreationInfo: creationInfo{
			Created:  createdAt.UTC().Format("2006-01-02T15:04:05Z"),
			Creators: []string{"Organization: /dev/null GmbH", "Tool: scripts/generate-release-sbom.go"},
		},
		Packages:      packages,
		Relationships: relationships,
	}

	file, err := os.Create(*output)
	if err != nil {
		fatalf("create output: %v", err)
	}
	encoder := json.NewEncoder(file)
	encoder.SetEscapeHTML(false)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(doc); err != nil {
		_ = file.Close()
		fatalf("encode SPDX document: %v", err)
	}
	if err := file.Close(); err != nil {
		fatalf("close output: %v", err)
	}
}

func findModuleRoots(repositoryRoot string) ([]string, error) {
	var roots []string
	err := filepath.WalkDir(repositoryRoot, func(path string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() && path != repositoryRoot {
			switch entry.Name() {
			case ".git", "conformance-suite", "vendor":
				return filepath.SkipDir
			}
		}
		if !entry.IsDir() && entry.Name() == "go.mod" {
			roots = append(roots, filepath.Dir(path))
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(roots)
	if len(roots) == 0 || roots[0] != repositoryRoot {
		return nil, fmt.Errorf("repository root does not contain go.mod")
	}
	return roots, nil
}

func listModules(root string) ([]goModule, error) {
	command := exec.Command("go", "list", "-mod=readonly", "-m", "-json", "all")
	command.Dir = root
	output, err := command.Output()
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return nil, fmt.Errorf("%w: %s", err, strings.TrimSpace(string(exitErr.Stderr)))
		}
		return nil, err
	}

	decoder := json.NewDecoder(strings.NewReader(string(output)))
	var modules []goModule
	for {
		var module goModule
		if err := decoder.Decode(&module); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		modules = append(modules, module)
	}
	return modules, nil
}

func validateReleaseRootReplacement(
	repositoryRoot string,
	graphRoot string,
	rootModulePath string,
	tag string,
	module goModule,
) (string, bool) {
	if graphRoot == repositoryRoot || module.Path != rootModulePath ||
		module.Version != tag || module.Replace == nil || module.Replace.Version != "" {
		return "", false
	}

	replacementPath := module.Replace.Path
	if !filepath.IsAbs(replacementPath) {
		replacementPath = filepath.Join(graphRoot, replacementPath)
	}
	replacementPath, err := filepath.Abs(replacementPath)
	if err != nil || filepath.Clean(replacementPath) != filepath.Clean(repositoryRoot) {
		return "", false
	}

	note := fmt.Sprintf(
		"Approved local replacement: %s maps %s@%s to the release source root",
		relativePath(repositoryRoot, graphRoot), module.Path, module.Version,
	)
	return note, true
}

func newPackage(path, version, purpose string) spdxPackage {
	return spdxPackage{
		Name:               path,
		SPDXID:             spdxID(path, version),
		VersionInfo:        version,
		DownloadLocation:   "NOASSERTION",
		FilesAnalyzed:      false,
		LicenseConcluded:   "NOASSERTION",
		LicenseDeclared:    "NOASSERTION",
		CopyrightText:      "NOASSERTION",
		PrimaryPackageType: purpose,
	}
}

func addRelationship(items map[string]relationship, item relationship) {
	key := strings.Join([]string{
		item.SPDXElementID,
		item.RelationshipType,
		item.RelatedSPDXElement,
	}, "\x00")
	items[key] = item
}

func relativePath(root, path string) string {
	relative, err := filepath.Rel(root, path)
	if err != nil || relative == "." {
		return "."
	}
	return filepath.ToSlash(relative)
}

func relativePaths(root string, paths []string) []string {
	values := make([]string, 0, len(paths))
	for _, path := range paths {
		values = append(values, relativePath(root, path))
	}
	return values
}

func spdxID(path, version string) string {
	digest := sha256.Sum256([]byte(path + "@" + version))
	return "SPDXRef-Package-" + hex.EncodeToString(digest[:])
}

func fatalf(format string, values ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", values...)
	os.Exit(1)
}
