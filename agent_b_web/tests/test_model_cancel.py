import threading
import time
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from agent_b_harness.clients import Model


class SlowHandler(BaseHTTPRequestHandler):
    started = threading.Event()

    def do_POST(self):
        self.started.set()
        time.sleep(4)

    def log_message(self, *_):
        pass


class ModelCancelTests(unittest.TestCase):
    def test_cancel_interrupts_inflight_response_wait(self):
        server = ThreadingHTTPServer(("127.0.0.1", 0), SlowHandler)
        server.daemon_threads = True
        serving = threading.Thread(target=server.serve_forever, daemon=True)
        serving.start()
        model = Model(
            f"http://127.0.0.1:{server.server_port}/v1",
            "test-key",
            "test-model",
            30,
            512,
        )
        finished = threading.Event()

        def request():
            try:
                model.complete([{"role": "user", "content": "wait"}], [])
            except Exception:
                pass
            finally:
                finished.set()

        worker = threading.Thread(target=request, daemon=True)
        worker.start()
        self.assertTrue(SlowHandler.started.wait(1), "model request did not start")
        model.cancel()
        self.assertTrue(finished.wait(1), "cancel did not interrupt the model request")
        server.shutdown()
        server.server_close()


if __name__ == "__main__":
    unittest.main()
