package ubuntu

import (
	"bufio"
	"bytes"
	"os"
	"regexp"
	"strings"

	"golang.org/x/xerrors"

	"github.com/aquasecurity/fanal/analyzer"
	aos "github.com/aquasecurity/fanal/analyzer/os"
	"github.com/aquasecurity/fanal/types"
	"github.com/aquasecurity/fanal/utils"
)

func init() {
	analyzer.RegisterAnalyzer(&ubuntuOSAnalyzer{})
}

var requiredFiles = []string{"etc/lsb-release"}

type ubuntuOSAnalyzer struct{}

var ubuntuVersionRegexp = regexp.MustCompile(`[\d.]+`)

func (a ubuntuOSAnalyzer) Analyze(content []byte) (analyzer.AnalyzeReturn, error) {
	isUbuntu := false
	ubuntuVer, ubuntuDetailedVer := "", ""

	scanner := bufio.NewScanner(bytes.NewBuffer(content))
	for scanner.Scan() {
		line := scanner.Text()

		if line == "DISTRIB_ID=Ubuntu" {
			isUbuntu = true
		}
		// Release contains only the release version of Ubuntu (e.g. 18.04)
		// Since we want to more detailed version, dont overwrite if it was set
		if ubuntuVer == "" && strings.HasPrefix(line, "DISTRIB_RELEASE=") {
			ubuntuVer = strings.TrimSpace(line[16:])
		}
		// Description contains the detailed version of Ubuntu (e.g. 18.04.2)
		if strings.HasPrefix(line, "DISTRIB_DESCRIPTION=") {
			ubuntuDetailedVer = ubuntuVersionRegexp.FindString(line)
		}
	}

	finalVer := ubuntuDetailedVer
	if finalVer == "" {
		finalVer = ubuntuVer
	}

	if isUbuntu {
		return analyzer.AnalyzeReturn{
			OS: types.OS{
				Family: aos.Ubuntu,
				Name:   finalVer,
			},
		}, nil
	}

	return analyzer.AnalyzeReturn{}, xerrors.Errorf("ubuntu: %w", aos.AnalyzeOSError)
}

func (a ubuntuOSAnalyzer) Required(filePath string, _ os.FileInfo) bool {
	return utils.StringInSlice(filePath, requiredFiles)
}

func (a ubuntuOSAnalyzer) Name() string {
	return aos.Ubuntu
}
