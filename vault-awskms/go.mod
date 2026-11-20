module github.com/OpenProdkt/governance-sdk-go-awskms

go 1.24

require (
	github.com/OpenProdkt/governance-sdk-go v0.9.0
	github.com/aws/aws-sdk-go-v2 v1.47.0
	github.com/aws/aws-sdk-go-v2/config v1.32.34
	github.com/aws/aws-sdk-go-v2/service/kms v1.60.0
	github.com/aws/smithy-go v1.28.1
)

require (
	github.com/aws/aws-sdk-go-v2/credentials v1.19.33 // indirect
	github.com/aws/aws-sdk-go-v2/feature/ec2/imds v1.18.34 // indirect
	github.com/aws/aws-sdk-go-v2/internal/configsources v1.5.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/endpoints/v2 v2.8.3 // indirect
	github.com/aws/aws-sdk-go-v2/internal/v4a v1.4.35 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/accept-encoding v1.13.15 // indirect
	github.com/aws/aws-sdk-go-v2/service/internal/presigned-url v1.13.34 // indirect
	github.com/aws/aws-sdk-go-v2/service/signin v1.5.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/sso v1.33.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/ssooidc v1.38.3 // indirect
	github.com/aws/aws-sdk-go-v2/service/sts v1.45.3 // indirect
)

replace github.com/OpenProdkt/governance-sdk-go => ../
