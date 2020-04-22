/// documentation on github : https://github.com/lscalese/isc-jwt <br/>
Class dc.auth.jwt.JWTGenerator Extends %RegisteredObject
{

Parameter HS256ALG = "HS256";

Parameter TYP = "JWT";

Property validityInSec As %Integer [ InitialExpression = 3600 ];

Property secret As %String;

Property header As %DynamicObject;

Property payload As %DynamicObject;

Property signature As %DynamicObject;

Property token As %String;

ClassMethod generate(secret As %String, validityInSec As %Integer = 3600, payload As %DynamicObject = {{}}, mergePayLoad As %Boolean = 1, ByRef jwt As dc.auth.jwt.JWTGenerator) As %String
{
    Set jwt = ..%New()
    Set jwt.secret = secret
    Set jwt.header = jwt.genHeader()

    If mergePayLoad {
        Set jwt.payload = jwt.genPayload(payload)
    } Else {
        Set jwt.payload = payload
    }

    Set jwt.token = jwt.genToken()
    Return jwt.token
}

Method genToken() As %String
{
    Set token = $System.Encryption.Base64Encode(..header.%ToJSON(),1)
                    _ "."
                    _ $System.Encryption.Base64Encode(..payload.%ToJSON(),1)
    
    Set token = $Translate(token,"+/=","-_") ; Base64URLEncode

    Set signature = $Translate($System.Encryption.Base64Encode( $System.Encryption.HMACSHA(256,token, ..secret), 1),"+/=","-_")

    Return token _ "." _ signature
}

Method getSignature() As %String
{
    Set token = $System.Encryption.Base64Encode(..header.%ToJSON(),1)
                    _ "."
                    _ $System.Encryption.Base64Encode(..payload.%ToJSON(),1)
     Set token = $Translate(token,"+/=","-_") ; Base64URLEncode
    Set signature = $Translate($System.Encryption.Base64Encode( $System.Encryption.HMACSHA(256,token, ..secret), 1),"+/=","-_")
    Return signature
}

Method %OnNew() As %Status
{
    Return $$$OK
}

Method genHeader() As %DynamicObject
{
    Return { "alg" : (..#HS256ALG), "typ" : (..#TYP) }
}

Method genPayload(payloadData As %DynamicObject = {{}}) As %DynamicObject
{
    Set jti = ..getJti()
    Set:'payloadData.%IsDefined("iat") payloadData.iat = $ZDatetime($Horolog,-2)
    Set:'payloadData.%IsDefined("sub") payloadData.sub = $Username
    Set:'payloadData.%IsDefined("iss") payloadData.iss = ##class(%SYS.System).GetInstanceName() _ "-" _ $Namespace
    Set:'payloadData.%IsDefined("exp") payloadData.exp = $ZDatetime($Horolog,-2) + ..validityInSec
    Set:'payloadData.%IsDefined("nbf") payloadData.nbf = payloadData.iat
    Set:'payloadData.%IsDefined("jti") payloadData.jti = jti
    Return payloadData
}

Method getJti() As %Integer
{
    Set jti = 97 + $Increment(^JWTGeneratorC)
    Return jti _ $Translate($Justify(jti #97 ,2)," ","0")
}

ClassMethod isValid(jwt As %String, secret As %String, ByRef sc As %Status, payloadMatch As %DynamicObject = {{}}, ByRef jwtObj As dc.auth.jwt.JWTGenerator, dateTime = { $ZDatetime($Horolog,-2)}) As %Boolean
{
    Set sc = $$$OK
    Set jwtObj = ..%New()
    Try {
        Set jwtObj.secret = secret
        Set jsonHeader = $SYSTEM.Encryption.Base64Decode($Translate($Piece(jwt,".",1),"-_","+/"))
        Set jsonPayload = $SYSTEM.Encryption.Base64Decode($Translate($Piece(jwt,".",2),"-_","+/"))
        Set encryptedSignature = $Piece(jwt,".",3)
        Set jwtObj.header = {}.%FromJSON(jsonHeader)
        Set jwtObj.payload = {}.%FromJSON(jsonPayload)

        If jwtObj.header.typ '= ..#TYP {
            Set sc = $$$ERROR(5001,"Bad token 'typ'.")
            Return $$$NO
        }

        If jwtObj.header.alg '= ..#HS256ALG {
            Set sc = $$$ERROR(5001,"Bad encyption algorithm.")
            Return $$$NO
        }

        Set verifiedSignature = jwtObj.getSignature()
        If (verifiedSignature '= encryptedSignature) {
            Set sc = $$$ERROR(5001,"Signature Mismatch.")
            Return $$$NO
        }

        Set dateTime = $ZDatetime($Horolog,-2)
        If jwtObj.payload.%IsDefined("exp") {
            If dateTime > jwtObj.payload.exp {
                Set sc = $$$ERROR(5001,"Token expired.")
                Return $$$NO
            }
        }

        If jwtObj.payload.%IsDefined("nbf") {
            If dateTime < jwtObj.payload.nbf {
                Set sc = $$$ERROR(5001,"Token cannot be used yet.")
                Return $$$NO
            }
        }
        
        Set iter = payloadMatch.%GetIterator()
        While iter.%GetNext(.key , .value ) {
            If '$Isobject(value) {
                If jwtObj.payload.%Get(key) '= value {
                    Set sc = $$$ERROR(5001, key _ " mismatch.")
                    Return $$$NO
                } 
            } Else {
                Set array = ##class(%ArrayOfDataTypes).%New()
                Do ##class(%ZEN.Auxiliary.jsonProvider).%ConvertJSONToObject(value.%ToJSON(),,.array)
                If array.Find(jwtObj.payload.%Get(key)) = "" {
                    Set sc = $$$ERROR(5001, key _ " mismatch.")
                    Return $$$NO
                }
            }
        }
    } Catch (ex) {
        Set sc = ex.AsStatus()
    }
    Return $Select($$$ISOK(sc):$$$YES,1:$$$NO)
}

}
