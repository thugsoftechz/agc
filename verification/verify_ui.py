from playwright.sync_api import sync_playwright

def verify_chat_interface():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        context = browser.new_context()
        page = context.new_page()

        # 1. Navigate to the web app
        try:
            page.goto("http://localhost:5000", timeout=10000)

            # 2. Interact with Login Modal
            page.wait_for_selector("#login-modal", state="visible")
            page.fill("#username-input", "TestUser")
            page.click("#join-btn")

            # 3. Wait for Chat Interface
            page.wait_for_selector("#app-container", state="visible")
            page.wait_for_selector(".chat-header", state="visible")

            # 4. Send a test message
            page.fill("#message-input", "Hello from Playwright!")
            page.click("#send-btn")

            # 5. Wait for message to appear
            page.wait_for_selector(".message.sent", state="visible")

            # 6. Take Screenshot
            page.screenshot(path="/home/jules/verification/chat_verification.png")
            print("[SUCCESS] Screenshot captured.")

        except Exception as e:
            print(f"[ERROR] {e}")
            page.screenshot(path="/home/jules/verification/error_state.png")

        finally:
            browser.close()

if __name__ == "__main__":
    verify_chat_interface()
