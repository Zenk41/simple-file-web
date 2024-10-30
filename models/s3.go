package models

type File struct {
	Name string `json:"name"` // Name of the file
	Key  string `json:"key"`  // S3 key for the file
}

type Folder struct {
	Name    string   `json:"name"`  // Name of the folder
	Key     string   `json:"key"`   // S3 key for the folder
	Files   []File   `json:"files"` // List of files in the folder
	Folders []Folder `json:"folders"`
}

type S3Response struct {
	Folders []Folder `json:"folders"` // List of folders
}

type ConfigS3 struct {
	S3AccessKey string `json:"s3accesskey"`
	S3SecretKey string `json:"s3secretkey"`
	S3Region    string `json:"s3region"`
	S3URL       string `json:"s3url"`
}


func (cfg *ConfigS3) IsEmpty() bool {
	return cfg.S3AccessKey == "" || cfg.S3SecretKey == "" ||
		cfg.S3Region == "" || cfg.S3URL == ""
}

func (cfg *ConfigS3) FillConfig(input ConfigS3) {

	cfg.S3AccessKey = input.S3AccessKey
	cfg.S3SecretKey = input.S3SecretKey
	cfg.S3Region = input.S3Region
	cfg.S3URL = input.S3URL

}
