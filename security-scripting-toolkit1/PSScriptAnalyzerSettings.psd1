@{
    Severity     = @('Error', 'Warning')
    # Tests use Write-Host for readable pass/fail output.
    ExcludeRules = @('PSAvoidUsingWriteHost')
}
