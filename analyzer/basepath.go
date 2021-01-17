package analyzer

var basePath = ""

func SetBasePath(path string) {
	basePath = path
}

func GetBasePath() string {
	return basePath
}
