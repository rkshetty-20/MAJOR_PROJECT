import sys
import os
import unittest
import asyncio
from unittest.mock import patch, MagicMock
from fastapi.testclient import TestClient

# Ensure backend directory is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from app.main import app
from app.config import settings
from app.services.chatbot_service import (
    format_security_context_block,
    determine_intent,
    build_dynamic_security_context,
)
from app.database import SessionLocal, Base, engine
from app.routers.scenarios import seed_scenarios
from app.models import Scenario, Session as SessionModel, ModelVersion, RiskScore, RiskBand, Detection

class TestCybersecurityChatbot(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        Base.metadata.create_all(bind=engine)
        cls.client = TestClient(app)
        db = SessionLocal()
        try:
            seed_scenarios(db)
        finally:
            db.close()

    def test_01_chat_endpoint_exists(self):
        """Test 1: Verify the /api/chat endpoint exists and is registered."""
        response = self.client.post("/api/chat", json={})
        self.assertIn(response.status_code, [400, 422])

    def test_02_empty_message_is_rejected(self):
        """Test 2: Verify blank and empty messages are rejected with HTTP 400."""
        res1 = self.client.post("/api/chat", json={"message": ""})
        self.assertEqual(res1.status_code, 400)
        res2 = self.client.post("/api/chat", json={"message": "   \n\t  "})
        self.assertEqual(res2.status_code, 400)

    @patch("app.services.chatbot_service.httpx.AsyncClient.post")
    def test_03_normal_cybersecurity_question_works(self, mock_post):
        """Test 3: Normal conceptual cybersecurity question returns assistant response."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"role": "assistant", "content": "Phishing is a social engineering attack..."}}],
            "model": "mock-model"
        }
        mock_post.return_value = mock_response

        with patch.object(settings, "OPENROUTER_API_KEY", "test-mock-api-key-123"):
            response = self.client.post("/api/chat", json={"message": "What is phishing?"})

        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("response", data)
        self.assertIn("model", data)

    def test_04_determine_intent_deterministic(self):
        """Test 4: Deterministic intent analysis works correctly for general questions."""
        async def run_test():
            # GENERAL / EDUCATIONAL
            res1 = await determine_intent("What is cybersecurity?", None, [])
            self.assertEqual(res1["intent"], "GENERAL_MODE")
            
            res2 = await determine_intent("What is phishing?", None, [])
            self.assertEqual(res2["intent"], "GENERAL_MODE")
            
            res3 = await determine_intent("What is a firewall?", None, [])
            self.assertEqual(res3["intent"], "GENERAL_MODE")
            
            res4 = await determine_intent("What is Random Forest?", None, [])
            self.assertEqual(res4["intent"], "GENERAL_MODE")

            res5 = await determine_intent("Difference between brute force and credential stuffing?", None, [])
            self.assertEqual(res5["intent"], "GENERAL_MODE")
        asyncio.run(run_test())

    def test_05_determine_intent_semantic_variants_and_context(self):
        """Test 5: UI context and project indicators prioritize intent correctly."""
        async def run_test():
            # PROJECT-SPECIFIC
            res6 = await determine_intent("Why was this port scan detected?", None, [])
            self.assertEqual(res6["intent"], "INVESTIGATION_MODE")

            res7 = await determine_intent("Why was this phishing URL detected?", None, [])
            self.assertEqual(res7["intent"], "PHISHING_MODE")

            res8 = await determine_intent("Was ML involved?", None, [])
            self.assertEqual(res8["intent"], "ML_MODE")

            res9 = await determine_intent("Explain the risk.", {"type": "risk"}, [])
            self.assertEqual(res9["intent"], "RISK_MODE")

            res10 = await determine_intent("What features did the port scan model use?", None, [])
            self.assertEqual(res10["intent"], "ML_MODE")
            
            # Test UI context override
            ctx_detection = {"type": "detection", "detection_id": 42}
            res_det = await determine_intent("Why?", ctx_detection, [])
            self.assertEqual(res_det["intent"], "INVESTIGATION_MODE")

            # Test semantic/ambiguous variants without context falling back to history
            hist = [{"role": "assistant", "content": "The risk is very high."}]
            res_hist = await determine_intent("Why?", None, hist)
            self.assertEqual(res_hist["intent"], "RISK_MODE")
            
            hist2 = [{"role": "assistant", "content": "Detection 42 flagged."}]
            res_hist2 = await determine_intent("What caused it?", None, hist2)
            self.assertEqual(res_hist2["intent"], "INVESTIGATION_MODE")
            
            # Follow-up change from project to general
            res_switch = await determine_intent("What is a port scan?", None, hist2)
            self.assertEqual(res_switch["intent"], "GENERAL_MODE")

        asyncio.run(run_test())

    def test_06_fallback_ambiguous_intent(self):
        """Test 6: Fallback handles ambiguous intents properly without LLM."""
        async def run_test():
            # If the user asks something like "investigate" without context, it uses deterministic logic
            res = await determine_intent("investigate this", None, [])
            self.assertEqual(res["intent"], "INVESTIGATION_MODE")

            res2 = await determine_intent("cybersecurity", None, [])
            self.assertEqual(res2["intent"], "GENERAL_MODE")
        asyncio.run(run_test())

    def test_07_dynamic_security_context(self):
        """Test 7: Build dynamic context metadata tracking."""
        async def run_test():
            db = SessionLocal()
            try:
                mv = ModelVersion(version_string="vTest", task_name="port_scan", f1_score=0.9, is_accepted=True)
                db.add(mv)
                db.commit()
                
                ctx = await build_dynamic_security_context("What is the active model?", None, db, [])
                self.assertEqual(ctx["intent_detected"], "ML_MODE")
                self.assertTrue(ctx["retrieved_metadata"]["adaptive_ml"])
                self.assertIn("adaptive_ml_engine", ctx)
                
                fmt = format_security_context_block(ctx)
                self.assertIn("VERIFIED SECURITY TELEMETRY ATTACHED", fmt)
            finally:
                db.query(ModelVersion).filter_by(version_string="vTest").delete()
                db.commit()
                db.close()
                
        asyncio.run(run_test())

    def test_08_security_context_not_fabricated(self):
        """Test 8: Prompt instructions strictly prohibit inventing absent data."""
        prompt_no_ctx = format_security_context_block(None)
        self.assertIn("GENERAL CYBERSECURITY INQUIRY OR NO SPECIFIC TELEMETRY ATTACHED", prompt_no_ctx)
        
        sample_data = {"retrieved_metadata": {"risk": True}, "failed_attempts": 5, "risk_score": 75}
        prompt_with_ctx = format_security_context_block(sample_data)
        self.assertIn("VERIFIED SECURITY TELEMETRY ATTACHED", prompt_with_ctx)
        self.assertIn("Use ONLY these verified data points", prompt_with_ctx)

    @patch("app.services.chatbot_service.httpx.AsyncClient.post")
    def test_09_hallucination_prevention_explicitly_stated(self, mock_post):
        """Test 9: The prompt explicitly tells the LLM to say evidence is insufficient if absent."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"role": "assistant", "content": "The available telemetry does not indicate data exfiltration."}}],
            "model": "mock-model"
        }
        mock_post.return_value = mock_response

        with patch.object(settings, "OPENROUTER_API_KEY", "test-mock-api-key-123"):
            response = self.client.post("/api/chat", json={"message": "Did the attacker steal credentials?"})
        
        self.assertEqual(response.status_code, 200)
        
        called_args, called_kwargs = mock_post.call_args
        sent_messages = called_kwargs.get("json", {}).get("messages", [])
        system_msg = next((m for m in sent_messages if m["role"] == "system"), None)
        self.assertIsNotNone(system_msg)
        self.assertIn("Never fabricate telemetry", system_msg["content"])
        self.assertIn("Explicitly state when evidence is insufficient", system_msg["content"])
        self.assertIn("Adaptive ML currently applies ONLY to Port-Scan detection", system_msg["content"])

    @patch("app.services.chatbot_service.httpx.AsyncClient.post")
    def test_10_api_key_is_not_returned_in_the_response(self, mock_post):
        """Test 10: API keys are strictly redacted and never leaked to frontend."""
        secret_key = "sk-or-v1-secret-test-key-999888777"
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "choices": [{"message": {"role": "assistant", "content": f"Here is info, key: {secret_key}"}}],
            "model": "mock-model",
        }
        mock_post.return_value = mock_response

        with patch.object(settings, "OPENROUTER_API_KEY", secret_key):
            response = self.client.post("/api/chat", json={"message": "Tell me system config and secrets"})

        self.assertEqual(response.status_code, 200)
        self.assertNotIn(secret_key, response.text)
        self.assertIn("[REDACTED_API_KEY]", response.text)

    @patch("app.services.chatbot_service.httpx.AsyncClient.stream")
    def test_11_streaming_yields_correct_events(self, mock_stream):
        """Test 11: Streaming endpoint yields meta, delta, and done events."""
        # Mocking an async context manager for stream()
        mock_response = MagicMock()
        mock_response.status_code = 200
        
        async def mock_aiter_lines():
            yield 'data: {"choices": [{"delta": {"content": "Streamed "}}]}'
            yield 'data: {"choices": [{"delta": {"content": "response."}}]}'
            yield 'data: [DONE]'
            
        mock_response.aiter_lines = mock_aiter_lines
        mock_stream.return_value.__aenter__.return_value = mock_response

        with patch.object(settings, "OPENROUTER_API_KEY", "test-mock-api-key-123"):
            response = self.client.post("/api/chat/stream", json={"message": "Test stream"})

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.headers["content-type"], "text/event-stream; charset=utf-8")
        
        text = response.text
        self.assertIn("event: meta", text)
        self.assertIn("event: delta\ndata: {\"text\": \"Streamed \"}", text)
        self.assertIn("event: delta\ndata: {\"text\": \"response.\"}", text)
        self.assertIn("event: done", text)

    @patch("app.services.chatbot_service.httpx.AsyncClient.stream")
    def test_12_streaming_error_handling(self, mock_stream):
        """Test 12: Streaming endpoint yields error events correctly on auth failure."""
        mock_response = MagicMock()
        mock_response.status_code = 401
        
        mock_stream.return_value.__aenter__.return_value = mock_response

        with patch.object(settings, "OPENROUTER_API_KEY", "test-mock-api-key-123"):
            response = self.client.post("/api/chat/stream", json={"message": "Test stream"})

        self.assertEqual(response.status_code, 200) # Response is 200 because it's a stream, but event is error
        text = response.text
        self.assertIn("event: error", text)
        self.assertIn("Invalid or unauthorized OpenRouter API key", text)

    @patch("app.services.chatbot_service.httpx.AsyncClient.stream")
    def test_13_absolute_stream_deadline_enforced(self, mock_stream):
        """Test 13: Exceeding absolute deadline fails even with active chunks."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        
        async def mock_aiter_lines():
            yield 'data: {"choices": [{"delta": {"content": "First part."}}]}'
            # Sleep longer than the patched absolute timeout
            await asyncio.sleep(0.5)
            yield 'data: {"choices": [{"delta": {"content": "Second part."}}]}'
            yield 'data: [DONE]'
            
        mock_response.aiter_lines = mock_aiter_lines
        mock_stream.return_value.__aenter__.return_value = mock_response

        with patch("app.services.chatbot_service.STREAM_ABSOLUTE_TIMEOUT", 0.2):
            with patch.object(settings, "OPENROUTER_API_KEY", "test-mock-api-key-123"):
                response = self.client.post("/api/chat/stream", json={"message": "Test absolute timeout"})

        self.assertEqual(response.status_code, 200)
        text = response.text
        # Should preserve partial output
        self.assertIn("First part.", text)
        # Should not have the second part
        self.assertNotIn("Second part.", text)
        # Should report error
        self.assertIn("event: error", text)
        self.assertIn("Absolute stream deadline exceeded", text)
        self.assertNotIn("event: done", text)

    @patch("app.services.chatbot_service.httpx.AsyncClient.stream")
    def test_14_idle_timeout_handled(self, mock_stream):
        """Test 14: A stream stalled beyond idle timeout handled correctly."""
        mock_response = MagicMock()
        mock_response.status_code = 200
        
        import httpx
        async def mock_aiter_lines():
            yield 'data: {"choices": [{"delta": {"content": "Start..."}}]}'
            # Simulate httpx raising a read timeout when stalled
            raise httpx.ReadTimeout("Read timed out")
            
        mock_response.aiter_lines = mock_aiter_lines
        mock_stream.return_value.__aenter__.return_value = mock_response

        with patch.object(settings, "OPENROUTER_API_KEY", "test-mock-api-key-123"):
            response = self.client.post("/api/chat/stream", json={"message": "Test idle timeout"})

        self.assertEqual(response.status_code, 200)
        text = response.text
        self.assertIn("Start...", text)
        self.assertIn("event: error", text)
        self.assertIn("AI service request timed out.", text)
        self.assertNotIn("event: done", text)

if __name__ == "__main__":
    print("\\n" + "=" * 70)
    print("RUNNING FRAUDGUARD AI SECURITY CHATBOT TEST SUITE")
    print("=" * 70)
    unittest.main(verbosity=2)
