"""
UI walkthrough: drives the running prototype in a real (headless) Chromium through the
full report lifecycle as each role and saves screenshots to docs/screenshots/.

Prereqs: API on :3001 (seeded with `npm run seed`), web on :3000.
Run:     python3 docs/e2e_ui_walkthrough.py
"""
import json
import os
import sys
import urllib.request
from playwright.sync_api import sync_playwright

WEB = os.environ.get("WEB", "http://localhost:3000")
API = os.environ.get("API", "http://localhost:3001")
PASSWORD = os.environ.get("SEED_PASSWORD", "Demo-Passw0rd!")
OUT = os.path.join(os.path.dirname(__file__), "screenshots")
os.makedirs(OUT, exist_ok=True)
log = []


def shot(page, name):
    page.wait_for_timeout(400)
    page.screenshot(path=os.path.join(OUT, f"{name}.png"), full_page=True)
    log.append(name)


def api(path, token=None, body=None):
    req = urllib.request.Request(API + path, method="POST" if body is not None else "GET",
                                 data=json.dumps(body).encode() if body is not None else None,
                                 headers={"Content-Type": "application/json",
                                          **({"Authorization": f"Bearer {token}"} if token else {})})
    with urllib.request.urlopen(req) as r:
        return json.loads(r.read() or "null")


def login(page, email):
    page.goto(f"{WEB}/login")
    page.fill("#email", email)
    page.fill("#password", PASSWORD)
    page.click("button:has-text('Sign in')")
    page.wait_for_url(lambda u: "/login" not in u)


def logout(page):
    page.click("button:has-text('Sign out')")
    page.wait_for_url("**/login")


def click(page, text):
    page.click(f"button:has-text('{text}')")
    page.wait_for_timeout(700)


with sync_playwright() as p:
    browser = p.chromium.launch()
    page = browser.new_page(viewport={"width": 1280, "height": 860})

    # 1. public catalog
    page.goto(WEB)
    page.wait_for_selector("text=e-Services Citizen Portal")
    shot(page, "01_public_catalog")

    # 2. researcher: Safe Harbor + submission
    login(page, "researcher@cyberhunt.test")
    page.goto(f"{WEB}/programs/1")
    page.wait_for_selector("text=Published reward matrix")
    shot(page, "02_program_safe_harbor")
    click(page, "Accept Safe Harbor")
    form = page.locator("form")
    form.locator("select").first.select_option("IDOR")
    form.locator("input").nth(0).fill("https://portal.agency-a.test/api/applications/1043")
    form.locator("input").nth(1).fill("IDOR in application status endpoint exposes other applicants")
    areas = form.locator("textarea")
    areas.nth(0).fill("The endpoint returns the application of any applicant when the numeric id is changed. "
                      "No ownership check is performed on the server side.")
    areas.nth(1).fill("1. Log in as test user A. 2. Open own application 1043. 3. Change the id to 1044. "
                      "4. The response contains test user B's application.")
    areas.nth(2).fill("Disclosure of name, IIN and address of other applicants.")
    areas.nth(3).fill("Request to the application endpoint with id 1044 using test user A's session.")
    # CVSS: PR=Low, C=High  -> AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N
    cv = form.locator("div:has(> span:has-text('CVSS v3.1')) select")
    cv.nth(2).select_option("L")
    cv.nth(5).select_option("H")
    shot(page, "03_submission_form")
    click(page, "Submit report")
    page.wait_for_selector("text=submitted")
    shot(page, "04_submission_result")
    report_id = page.locator("p:has-text('submitted')").inner_text().split()[1]
    logout(page)

    # second researcher files a near-duplicate through the API (exercises automatic duplicate check)
    t2 = api("/auth/login", body={"email": "researcher2@cyberhunt.test", "password": PASSWORD})["token"]
    api("/programs/1/safe-harbor", t2, {})
    api("/reports", t2, {
        "programId": 1, "vulnType": "IDOR",
        "title": "Application status IDOR exposes other applicants data",
        "target": "https://portal.agency-a.test/api/applications/1043",
        "description": "Changing the numeric application id returns another applicant record because the server performs no ownership check.",
        "steps": "1. Log in. 2. Open own application. 3. Change the id. 4. Another applicant's record is returned.",
        "impact": "Personal data of other applicants is disclosed.",
        "cvssVector": "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N"})

    # 3. operator: queue, triage, assessment
    login(page, "operator@cyberhunt.test")
    page.goto(f"{WEB}/reports")
    page.wait_for_selector("text=Triage queue")
    shot(page, "05_operator_queue")
    page.goto(f"{WEB}/reports")
    page.click("tbody tr:last-child a")
    page.wait_for_selector("text=Automatic checks")
    click(page, "Start triage")
    click(page, "Validated")
    click(page, "Accept (not a duplicate)")
    page.wait_for_selector("text=Severity assessment")
    sels = page.locator("div.card:has(> span:has-text('Severity assessment')) select")
    sels.nth(0).select_option("SEVERE")
    sels.nth(1).select_option("TRIVIAL_AUTOMATABLE")
    sels.nth(2).select_option("ALL_USERS")
    shot(page, "06_operator_assessment_form")
    click(page, "Assign severity")
    page.wait_for_selector("text=Model comparison")
    shot(page, "07_assessment_baseline_vs_multifactor")
    logout(page)

    # 4. payment committee (second approver)
    login(page, "admin@cyberhunt.test")
    page.goto(f"{WEB}/reports/{report_id}")
    page.wait_for_selector("text=Approve reward")
    click(page, "Approve reward")
    click(page, "Mark as paid")
    logout(page)

    # 5. agency: remediation
    login(page, "agency@cyberhunt.test")
    page.goto(f"{WEB}/reports/{report_id}")
    page.wait_for_selector("text=Start remediation")
    page.fill("input[placeholder='Responsible person / team']", "Head of IT Security, Agency A")
    page.fill("input[type=date]", "2026-12-01")
    click(page, "Start remediation")
    page.fill("textarea[placeholder='What was fixed']", "Server-side ownership check added to the applications endpoint.")
    click(page, "Submit fix for retest")
    logout(page)

    # 6. operator retest + analytics
    login(page, "operator@cyberhunt.test")
    page.goto(f"{WEB}/reports/{report_id}")
    page.wait_for_selector("text=Retest passed")
    click(page, "Retest passed")
    page.wait_for_selector("text=Retest: ")
    shot(page, "08_report_closed_history")
    page.goto(f"{WEB}/analytics")
    page.wait_for_selector("text=Audit chain")
    shot(page, "09_analytics_audit")
    logout(page)

    # 7. researcher view after payment + public leaderboard
    login(page, "researcher@cyberhunt.test")
    page.goto(f"{WEB}/reports")
    page.wait_for_selector("text=My reports")
    shot(page, "10_researcher_my_reports")
    page.goto(WEB)
    page.wait_for_selector("text=CH-DEMO01")
    shot(page, "11_leaderboard")

    # 8. IDOR check in the UI: second researcher opens the first researcher's report
    logout(page)
    login(page, "researcher2@cyberhunt.test")
    page.goto(f"{WEB}/reports/{report_id}")
    page.wait_for_selector("text=Report not found")
    shot(page, "12_idor_blocked")
    browser.close()

print("report:", report_id)
print("screenshots:", ", ".join(log))
sys.exit(0)
