"""Text red-flag rules for job and interview-invitation scams aimed at students.

Each rule explains the warning in plain language and says what to do. Severity
controls how much a rule counts. Rules are deliberately specific: the cost of a
false alarm (calling a real recruiter a scam) is as real as the cost of a miss.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

from .core import Finding


@dataclass(frozen=True)
class Rule:
    rule_id: str
    pattern: str
    title: str
    risk: str          # high | medium | low
    explanation: str
    advice: str


RULES: list[Rule] = [
    Rule("upfront_fee",
         r"(?:pay|send|deposit|purchase|buy)\b[^.\n]{0,60}\b(?:fee|deposit|kit|equipment|laptop|software|training|registration|background check|uniform|starter)"
         r"|(?:registration|training|processing|application|onboarding|security|background check)\s+(?:fee|charge|payment)",
         "Asks you to pay to get the job", "high",
         "A real employer pays you. It does not charge you for training, equipment, or paperwork.",
         "Do not pay. Stop replying and report the message."),
    Rule("check_or_transfer",
         r"(?:cash|deposit)\b[^.\n]{0,30}\bcheck\b|check will be (?:sent|mailed)|send (?:back|the (?:rest|remaining|balance))"
         r"|\bwire (?:the|transfer|money)|western union|money order|gift cards?|bitcoin|crypto(?:currency)?\b|\bzelle\b|cash ?app",
         "Mentions checks, transfers, gift cards or crypto", "high",
         "Fake-check scams send you a check, ask you to send money back, and the check later bounces, leaving you owing the bank.",
         "Never deposit a check and send money onward for a job. Report it."),
    Rule("chat_app_interview",
         r"(?:interview|chat|contact|reach)[^.\n]{0,60}(?:whatsapp|telegram|signal|google chat|hangouts|skype|text(?:ing)? only)"
         r"|(?:whatsapp|telegram|signal)\b[^.\n]{0,40}(?:interview|hr|recruiter)"
         r"|interview[^.\n]{0,30}(?:via|through|over|on)\s+(?:chat|text|messaging|instant messag)",
         "Moves the interview to a chat app", "high",
         "Real companies interview by video or phone through their own systems, not over a texting app.",
         "Ask for a video interview with a company email address. If they refuse, walk away."),
    Rule("data_before_interview",
         r"(?:social security|\bssn\b|bank account|routing number|passport|driver'?s license|id card|direct deposit|credit card)"
         r"(?=[^\n]*(?:interview|apply|application|registration|resume|candidate))"
         r"|(?:interview|apply|application|registration|resume|candidate)[^\n]*"
         r"(?:social security|\bssn\b|bank account|routing number|passport|driver'?s license|id card|direct deposit|credit card)",
         "Asks for sensitive data before a verified offer", "high",
         "Scammers collect ID and bank details early. Real employers ask for them after a verified written offer, through an official HR system.",
         "Do not send ID or bank details. Verify the company first."),
    Rule("registration_first",
         r"(?:must|need to|required to|have to)\b[^.\n]{0,40}(?:register|registration|complete|fill)[^\n]{0,80}(?:then only|only then|before|to (?:get|receive|be scheduled))[^\n]{0,40}interview"
         r"|(?:then only|only then)[^\n]{0,30}interview",
         "Makes you register before any interview", "high",
         "You are being asked to hand over details before anyone has said who the employer is. This pattern is common in lead-collection schemes.",
         "Do not register. Ask which company and role this is, and check the company's official careers page."),
    Rule("reshipping_jobs",
         r"mystery shopper|reship(?:ping)?|package forwarding|payment processing agent|personal assistant to (?:the )?(?:ceo|executive)|envelope stuffing",
         "Matches a known fake-job type", "high",
         "These job types are widely reported scam schemes that use you to move money or goods.",
         "Skip this offer."),
    Rule("data_entry_remote",
         r"data entry[^.\n]{0,40}(?:work from home|remote|work-from-home)",
         "Remote data-entry offer", "medium",
         "Easy remote data-entry work is a common bait for scams.",
         "Check the employer independently before sharing anything."),
    Rule("form_before_interview",
         r"(?:fill out|complete|submit)[^.\n]{0,30}(?:google form|application form|registration form|the form)[^\n]{0,80}(?:below|link)",
         "Sends you to a form to hand over details", "medium",
         "A form can collect personal data before you know who the employer is.",
         "Confirm the company and the role first, then apply on its official site."),
    Rule("generic_greeting",
         r"^\s*(?:dear|hi|hello|greetings)[,\s]+(?:candidate|applicant|job ?seeker|sir|madam|sir/madam|user|friend)\b",
         "Generic greeting, not addressed to you", "medium",
         "Mass mailings use 'Dear Candidate' because they do not know who you are.",
         "Treat it as a bulk message, not a personal invitation."),
    Rule("vague_employer",
         r"(?:our|a)\s+(?:client|partner)\s+company|(?:reputed|leading|top)\s+(?:mnc|company|organization|firm)|multinational company",
         "Does not name the employer", "medium",
         "Not naming the company means you cannot check it.",
         "Ask for the company name, role, and a link to the posting on its own site."),
    Rule("too_good",
         r"guaranteed (?:job|income|offer|placement)|100% (?:placement|job)|(?:earn|make)\s+\$?\d[\d,]*\s*(?:\+)?\s*(?:per|a|/)\s*(?:week|day)"
         r"|no (?:interview|experience) (?:is )?(?:needed|required|necessary)",
         "Promises that sound too good", "medium",
         "Guaranteed jobs or big pay for no experience are classic bait.",
         "Be skeptical and verify the company."),
    Rule("hired_on_spot",
         r"hired (?:immediately|on the spot|without (?:an )?interview)|you(?:'| a)re hired\b",
         "Says you are hired without a real process", "medium",
         "Real hiring involves a process. Instant offers are a warning sign.",
         "Ask for the process and the hiring manager's name."),
    Rule("urgency",
         r"(?:respond|reply|confirm|apply|register|pay)\b[^.\n]{0,40}(?:within|in the next)\s+(?:\d+|one|two)\s*(?:hours?|hrs?)"
         r"|limited (?:slots|positions|seats|vacancies)|act (?:now|fast|immediately)|offer (?:expires|will expire)|urgent(?:ly)? (?:hiring|requirement|opening)",
         "Pressure to act fast", "low",
         "Scammers rush you so you do not check.",
         "Take your time to verify."),
    Rule("mass_mailing",
         r"unsubscribe|opt out of all",
         "Looks like a mass mailing", "low",
         "An unsubscribe footer suggests a bulk list, not a personal invitation.",
         "Treat it as marketing until proven otherwise."),
]

_COMPILED = [(r, re.compile(r.pattern, re.I)) for r in RULES]
RULE_BY_ID = {r.rule_id: r for r in RULES}


def find(lines: list[tuple[int, str]]) -> list[Finding]:
    out: list[Finding] = []
    for line_id, text in lines:
        for rule, rx in _COMPILED:
            m = rx.search(text)
            if m:
                out.append(Finding(title=rule.title, explanation=rule.explanation, risk=rule.risk,
                                   line_ids=[line_id], quote=m.group(0).strip(),
                                   rule_id=rule.rule_id, advice=rule.advice, kind="text"))
    return out
