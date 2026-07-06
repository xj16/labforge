@{
    # PSScriptAnalyzer settings for labforge's Windows provisioning scripts.
    #
    # We EXCLUDE PSAvoidUsingConvertToSecureStringWithPlainText on purpose: the
    # Windows victim intentionally creates deliberately-WEAK, documented local
    # accounts (labuser/Password1, svc_backup/Summer2026) for password-attack
    # practice. Building those SecureStrings from literals is the whole point,
    # and it is safe ONLY because the lab is air-gapped (see ETHICS.md). This is
    # a lab target, never a production machine.
    Severity     = @('Error')
    ExcludeRules = @(
        'PSAvoidUsingConvertToSecureStringWithPlainText'
    )
}
