
Function Get-SSOToken {
    [CmdletBinding()]
    param (
        # [Parameter(Mandatory = $true)]
        [string]
        $ConfigFilePath,

        [string]
        $KeycloakServer = "https://*********",

        [string]
        $ClientID,

        [string]
        $ClientSecret,

        [Parameter()]
        $TokenOBJ,
        [bool] $hasTokenOBJ = $false
    )


    Begin {

        if(!$ConfigFilePath){$ConfigFilePath = Read-Host -Prompt "ConfigFilePath"}
        
        try{
            $ConfigFileOBJ = Get-Content ($ConfigFilePath) | Select | ConvertFrom-StringData
        }
        catch{
            Write-Host "Invalid ConfigFilePath" -ForegroundColor Red
            exit
        }

        if(!$ConfigFileOBJ.KeycloakServer -and !$ConfigFileOBJ.KeycloakServer -and !$ConfigFileOBJ.KeycloakServer) {
            Write-Host "Must have: [KeycloakServer, ClientID, ClientSecret]" -ForegroundColor Red
            exit
        }
        $KeycloakServer = $ConfigFileOBJ.KeycloakServer
        $ClientID = $ConfigFileOBJ.ClientID
        $ClientSecret = $ConfigFileOBJ.ClientSecret

        # $TokenOBJ = Read-Host -Prompt "Token (Leave empty if you don't have it)"
        if($TokenOBJ){
            $hasTokenOBJ = $true
        }
    }

    
    
    Process {
        $RequestURL = $KeycloakServer + "***********************"
        
        # Se for passado o $Token, verificar se pode ser renovado (veriricar data-hora de expiração). Renovar ou gerar um novo.
        # Caso contrário, gerar Token novo com as credenciais informadas.

        $HashObjetoToken = [ordered]@{
            'AccessToken'  = 'complexvalue'
            'RefreshToken' = 'complexvaluerefresh'
            'Expiracao'    = (Get-Date).AddMinutes(5)
        }


        if($hasTokenOBJ)
        {
            if((Get-Date) -lt $TokenOBJ.Expiracao){
                Write-Host ""
                $body = @{grant_type = 'refresh_token';
                client_id        = "$ClientID";
                client_secret    = "$ClientSecret";
                refresh_token    = $TokenOBJ.RefreshToken
                }

                # Token refresh request

                $token = Invoke-WebRequest -Method POST -Uri $RequestURL -ContentType "application/x-www-form-urlencoded" -Body $body

                # Write-Host $token
                $accessToken = (ConvertFrom-Json $token.content).access_token
                $refreshToken = (ConvertFrom-Json $Token.Content).refresh_token

        
                $NovoObjetoTokenRefresh = New-Object -TypeName PSObject -Property $HashObjetoToken

                $NovoObjetoTokenRefresh.AccessToken = $accessToken
                $NovoObjetoTokenRefresh.RefreshToken = $refreshToken

                

            }else{
                Write-Host "Your RefreshToken expired" -ForegroundColor Red
                Write-Host Time of Expiration: $TokenOBJ.Expiracao -ForegroundColor Red
            }
        }
        else{
    
            $NovoObjetoToken = New-Object -TypeName PSObject -Property $HashObjetoToken
            

            $body = @{grant_type = 'client_credentials';
                client_id        = "$ClientID";
                client_secret    = "$ClientSecret"
            }
    
            # Token Request
    
            $token = Invoke-WebRequest -Method POST -Uri $RequestURL -ContentType "application/x-www-form-urlencoded" -Body $body

            $accessToken = (ConvertFrom-Json $token.content).access_token
            $refreshToken = (ConvertFrom-Json $Token.Content).refresh_token
    
            $NovoObjetoToken.AccessToken = $accessToken
            $NovoObjetoToken.RefreshToken = $refreshToken
        }

    }

    End {
        if($hasTokenOBJ){
            Write-Host "Token Refresh"
            return $NovoObjetoTokenRefresh}
        else{
            Write-Host "New Token"
            return $NovoObjetoToken}
    }

    <#
        .SYNOPSIS
        Refresh or create a new SSOToken to use

        .DESCRIPTION
        Case 0 (config file):
            Takes KeycloakServer, ClientId and ClientSecret from
            a config file.
            "
                KeycloakServer = ############
                ClientID = ############
                ClientSecret = ############
            "

        Case 1 (new token):
            It will request a new TokenObj (with the cresentials
            from the config file) which will be returned 
            by the function.
            Can be Called as:
            "$obj = Get-SSOToken"

        Case 2 (Refresh Token):
            Takes same info as "Case 1" and a TokenOBJ.
            "$refObj = Get-SSOToken -TokenOBJ $obj"
            If the token isn't expired it will
            request to renew it's expiration time 
            and return a new Token Object

    #>

}

Function Get-TJAPIUserInfo {

    [CmdletBinding()]
    param (
        [Parameter()]
        [string]
        $APIURI = "https://integracaorh-api.apps.tjdft.jus.br/graphql",
        [Parameter()]
        $TokenOBJ,
        [Parameter(Mandatory = $true)]
        [ValidateSet("estagiarios", "estagiario", "servidor", "magistrado")]
        $TipoUsuario,
        [Parameter()]
        [ValidateSet("DESEMBARGADOR", "JUIZ_DIREITO", "JUIZ_SUBSTITUTO")]
        $MagistradoType,
        [Parameter()]
        $Matricula,
        [Parameter()]
        $Login,
        [Parameter()]
        $Nome,
        [switch]
        $IncluirUsuarioDesativado
    )

    begin {

        # Check if token is valid
        if (!$TokenObj -or !$TokenObj.Expiracao -or !$TokenObj.AccessToken -or !$TokenObj.RefreshToken) {
            Write-Host "Invalid or missing TokenOBJ" -ForegroundColor Red
            exit
        } 

        # Check token's expiration time
        $TimeSpan = (New-TimeSpan -Start $TokenOBJ.Expiracao -end (Get-Date))
        if($TimeSpan.Minutes -ge -2 -and $TimeSpan.Minutes -lt 0){
            Write-Host "Your Token will expire in less than " ($TimeSpan.Minutes * -1)" minutes consider refreshing it" -ForegroundColor Yellow
        } elseif($TimeSpan.Minutes -gt 0 -and $TimeSpan.Seconds -gt 30){
            write-Host $TimeSpan.Seconds
            write-Host "Your Token has expired!" -ForegroundColor Red
            exit
        }

        switch ($TipoUsuario) {
        #user type names modified for security
            user1 {
                if(!$MagistradoType){
                    Write-Host "Invalid -Matricula or -login" -ForegroundColor Red
                    exit
                }
            }
            user2 {
                if(!$Matricula -and !$login){
                    Write-Host "Invalid -Matricula or -login" -ForegroundColor Red
                    exit
                }
            }
            users2{
                if(!$Nome){
                    Write-Host "Invalid -Nome" -ForegroundColor Red
                    exit
                }
            }
            user3 {
                if(!$Matricula){
                    Write-Host "Invalid -Matricula" -ForegroundColor Red
                    exit
                }
            }
        }

    }

    process {
        
        # $ResultIsPaginator = $FALSE #if returns with paginator type


        switch ($TipoUsuario){
            user2 {
                $body = "query {
                    user2 (
                        $(if($Matricula){"matricula: """"$Matricula"""""})
                        $(if($login){"login: """"$login"""""})
                        ){
                        id
                        nome
                        matricula
                        login
                        dadosFuncionais {
                            localizacao {
                                id
                                codigo
                                sigla
                                nome
                                }
                            }
                        }
                    }"
            }
            users2 {
                $body = "query {
                    users2 (
                        $(if($Nome){"nome: """"$Nome"""""})
                        ){
                        data {
                            id
                            nome
                            matricula
                            login
                            dadosFuncionais {
                            localizacao {
                                id
                                codigo
                                sigla
                                nome
                                }
                            }
                        }
                    }
                }"
            }
            user3 {
                $body = "query {
                    user3 (
                        $(if($Matricula){"matricula: """"$Matricula"""""})
                        ){
                        id
                        nome
                        matricula
                        dadosFuncionais {
                            localizacao {
                                id
                                sigla
                                nome
                                }
                            }
                        }
                    }"
            }
            user4 {
                $body = "query {
                    user4 (
                        $(if($MagistradoType){"tipo: """"$user4Type"""""})
                        ){
                        data{
                            id
                            matricula
                            nome
                            sexo
                            login
                            }
                        }
                    }"
            }
        }
        
        
        $RequestBody = @{"query"=$body} | ConvertTo-Json

        $headers = @{
            "Content-Type" = "application/json"
            "Authorization" = "Bearer $($TokenOBJ.AccessToken)"
        }

    }

    end {

        # # Token Request
        $retorno = Invoke-WebRequest -Method POST -Headers $headers -Uri $APIURI -Body $RequestBody
        Write-Host $retorno
    
        # if(!$ResultIsPaginator)
        return ($retorno | ConvertFrom-Json).data


        

    }
}


# $Keycloak_Server = "https://**************"
# #$credentials = Get-Credential -Message "Please enter your Credentials"
# $Username = "************"
# $Password = "************"
