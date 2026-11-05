def calculate_confidence_score(
    pattern_matches: dict, comprehend_matches: list, context_keywords_found: bool
) -> float:
    """
    Calculates a confidence score (0.0 to 1.0) based on signals.
    """
    score = 0.0

    # Pattern Matches Weight (High confidence, especially with Luhn/format validation)
    total_pattern_matches = sum(len(matches) for matches in pattern_matches.values())
    if total_pattern_matches > 0:
        score += 0.4
        if total_pattern_matches > 3:
            score += 0.1  # Bonus for multiple hits

    # Context Keywords Weight
    if context_keywords_found:
        score += 0.3

    # Comprehend NLP Weight
    if len(comprehend_matches) > 0:
        score += 0.2
        # If Comprehend has high confidence on its findings, add more weight
        avg_comprehend_score = sum(match.get("Score", 0) for match in comprehend_matches) / len(
            comprehend_matches
        )
        if avg_comprehend_score > 0.8:
            score += 0.1

    # Cap score at 1.0 (100%)
    return min(1.0, score)


def determine_sensitivity_level(pattern_matches: dict, comprehend_matches: list) -> str:
    """
    Determines sensitivity level: RESTRICTED, CONFIDENTIAL, INTERNAL, PUBLIC
    RESTRICTED: IC numbers, Credit Cards
    CONFIDENTIAL: Emails, Phone numbers
    """
    if any(
        pattern_matches.get(data_type)
        for data_type in ("my_ic", "credit_card", "government_id", "financial_account")
    ):
        return "RESTRICTED"

    # Comprehend restricted categories
    restricted_types = ["SSN", "CREDIT_CARD_NUMBER", "PASSPORT_NUMBER", "BANK_ACCOUNT_NUMBER"]
    if any(match.get("Type") in restricted_types for match in comprehend_matches):
        return "RESTRICTED"

    if any(
        pattern_matches.get(data_type)
        for data_type in (
            "email",
            "my_phone",
            "name",
            "address",
            "matric_number",
            "date_of_birth",
        )
    ):
        return "CONFIDENTIAL"

    confidential_types = ["EMAIL", "PHONE", "NAME", "ADDRESS"]
    if any(match.get("Type") in confidential_types for match in comprehend_matches):
        return "CONFIDENTIAL"

    return "PUBLIC"
