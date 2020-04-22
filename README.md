![jwtimg](https://jwt.io/img/logo-asset.svg)
# JSON Web Token Generator

This is a simple class in order to generate and validate a [JSON Web Token](https://jwt.io).  
Signature is encrypted with HS256 algorithm.  

## Generate a token

### Basic
```
Set validityInSecond = 3600
Set jwt = ##class(dc.auth.jwt.JWTGenerator).generate("MySecretKey",validityInSecond)
```

Generated token `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpYXQiOjE1ODc1ODQ2OTksInN1YiI6ImlyaXNvd25lciIsImlzcyI6IklSSVMtSVJJU0FQUCIsImV4cCI6MTU4NzU4ODI5OSwibmJmIjoxNTg3NTg0Njk5LCJqdGkiOiIxMTExNCJ9.r-tyzZBPBE5_OeFjkr355QEztriswX3EkN68Ck9Em-M`

## Header
```
{
  "alg": "HS256",
  "typ": "JWT"
}
```

## Payload
```
{
  "iat": 1587584761,
  "sub": "irisowner",
  "iss": "IRIS-IRISAPP",
  "exp": 1587588361,
  "nbf": 1587584761,
  "jti": "11215"
}
```

### Customize payload

#### Add data and override default payload data : 

```
Set validityInSecond = 3600
Set addPayloadData = { "name" : "Mike Wazowski", "sub":"override sub property" }
Set jwt = ##class(dc.auth.jwt.JWTGenerator).generate("MySecretKey",validityInSecond,addPayloadData)
```

Generated token `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiTWlrZSBXYXpvd3NraSIsInN1YiI6Im92ZXJyaWRlIHN1YiBwcm9wZXJ0eSIsImlhdCI6MTU4NzU4NTcyMywiaXNzIjoiSVJJUy1JUklTQVBQIiwiZXhwIjoxNTg3NTg5MzIzLCJuYmYiOjE1ODc1ODU3MjMsImp0aSI6IjExNjE5In0.ZeV7J2KQKFO7l3ZZghrN0mLFhkhcErD80bTFdXXeIjo`  


Payload data : 

```
{
  "name": "Mike Wazowski",
  "sub": "override sub property",
  "iat": 1587585723,
  "iss": "IRIS-IRISAPP",
  "exp": 1587589323,
  "nbf": 1587585723,
  "jti": "11619"
}
```

#### Force payload value :

```
Set validityInSecond = 3600
Set payload = { "name" : "Mike Wazowski", "sub":"irisuser", "iat":1587584761,"exp":1587588361, "aud":"1.2.3.4" }
Set jwt = ##class(dc.auth.jwt.JWTGenerator).generate("MySecretKey",validityInSecond,payload,0)
```

Generated token `eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiTWlrZSBXYXpvd3NraSIsInN1YiI6ImlyaXN1c2VyIiwiaWF0IjoxNTg3NTg0NzYxLCJleHAiOjE1ODc1ODgzNjEsImF1ZCI6IjEuMi4zLjQifQ.zytuIRD56lvAnb-WnguIfbn9-t8RwSzfI_9PbBHzq8U`  

Payload data : 

```
{
  "name": "Mike Wazowski",
  "sub": "irisuser",
  "iat": 1587584761,
  "exp": 1587588361,
  "aud": "1.2.3.4"
}
```

If you passed by reference a fifth argument to generate classmethod you can retrieve the used dc.auth.jwt.JWTGenerator object instance.  

## Validate Token

### Basic validation

```
Set isValid = ##class(dc.auth.jwt.JWTGenerator).isValid(jwt,"MySecretKey",.sc)
```

If the token invalid, you can retrieve an error message with the status passed by reference
```
Write $SYSTEM.Status.GetOneErrorText(sc)
```
Ex: `ERROR #5001: Signature Mismatch.`

### Validation with additional matching payload data

```
Set payLoadMatch = {"name":"Mike Wazowski", "aud":"127.0.0.1"}
Set isValid = ##class(dc.auth.jwt.JWTGenerator).isValid(jwt,"MySecretKey",.sc,payLoadMatch)
Write $SYSTEM.Status.GetOneErrorText(sc)
```

Result : `ERROR #5001: aud mismatch.`

We can also check if aud value match in specific list : 

```
Set payLoadMatch = {"name":"Mike Wazowski", "aud":["127.0.0.1","1.2.3.4"]}
Set isValid = ##class(dc.auth.jwt.JWTGenerator).isValid(jwt,"MySecretKey",.sc,payLoadMatch)
Write $SYSTEM.Status.GetOneErrorText(sc)
```

Result : `OK`

If you passed by reference a fifth argument to isValid method you can retrieve the used dc.auth.jwt.JWTGenerator object instance.  

## Prerequisites
Make sure you have [git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) and [Docker desktop](https://www.docker.com/products/docker-desktop) installed.

## Installation 

Clone/git pull the repo into any local directory

```
$ git clone https://github.com/intersystems-community/objectscript-docker-template.git
```

Open the terminal in this directory and run:

```
$ docker-compose build
```

3. Run the IRIS container with your project:

```
$ docker-compose up -d
```

## How to start coding
This repository is ready to code in VSCode with ObjectScript plugin.
Install [VSCode](https://code.visualstudio.com/), [Docker](https://marketplace.visualstudio.com/items?itemName=ms-azuretools.vscode-docker) and [ObjectScript](https://marketplace.visualstudio.com/items?itemName=daimor.vscode-objectscript) plugin and open the folder in VSCode.
Open /src/cls/PackageSample/ObjectScript.cls class and try to make changes - it will be compiled in running IRIS docker container.
![docker_compose](https://user-images.githubusercontent.com/2781759/76656929-0f2e5700-6547-11ea-9cc9-486a5641c51d.gif)

Feel free to delete PackageSample folder and place your ObjectScript classes in a form
/src/Package/Classname.cls
[Read more about folder setup for InterSystems ObjectScript](https://community.intersystems.com/post/simplified-objectscript-source-folder-structure-package-manager)

The script in Installer.cls will import everything you place under /src into IRIS.


## What's inside the repository

### Dockerfile

The simplest dockerfile which starts IRIS and imports Installer.cls and then runs the Installer.setup method, which creates IRISAPP Namespace and imports ObjectScript code from /src folder into it.
Use the related docker-compose.yml to easily setup additional parametes like port number and where you map keys and host folders.
Use .env/ file to adjust the dockerfile being used in docker-compose.

### Dockerfile-zpm

Dockerfile-zpm builds for you a container which contains ZPM package manager client so you are able to install packages from ZPM in this container.
As an example of usage in installs webterminal

### Dockerfile-web

Dockerfile-web starts IRIS does the same what Dockerfile does and also sets up the web app programmatically


### .vscode/settings.json

Settings file to let you immedietly code in VSCode with [VSCode ObjectScript plugin](https://marketplace.visualstudio.com/items?itemName=daimor.vscode-objectscript))

### .vscode/launch.json
Config file if you want to debug with VSCode ObjectScript

[Read about all the files in this artilce](https://community.intersystems.com/post/dockerfile-and-friends-or-how-run-and-collaborate-objectscript-projects-intersystems-iris)
