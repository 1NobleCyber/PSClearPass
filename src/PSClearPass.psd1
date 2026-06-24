@{
    RootModule         = 'PSClearPass.psm1'
    ModuleVersion      = '0.0.1'
    GUID               = '4a9b3ae7-b5c0-49e3-8b72-bb0f3beb7efa'
    Author             = 'David Crawford'
    CompanyName        = 'Unknown'
    Copyright          = 'Unlicense license'
    Description        = 'A PowerShell module customized for interacting with internal ClearPass Web UI Data.'
    PowerShellVersion  = '5.1'
    RequiredModules    = @()
    RequiredAssemblies = @()
    ScriptsToProcess   = @()
    TypesToProcess     = @()
    FormatsToProcess   = @()

    # TODO: Do not use wildcards in actual version
    # During dev, we use '*' so I don't have to update this file every time we add a command.
    # Will control visibility inside the .psm1 file instead.
    FunctionsToExport  = '*'
    CmdletsToExport    = @()
    VariablesToExport  = '*'
    AliasesToExport    = @()

    PrivateData        = @{
        PSData = @{
            # Tags applied to this module. These help with module discovery in online galleries.
            Tags       = @('ClearPass', 'Security', 'Logs', 'API')

            # A URL to the license for this module.
            LicenseUri = 'https://github.com/1NobleCyber/PSClearPass#Unlicense-1-ov-file'

            # A URL to the main website for this project.
            ProjectUri = 'https://github.com/1NobleCyber/PSClearPass'
        }
    }
}
