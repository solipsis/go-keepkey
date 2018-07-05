from messages_pb2_twirp import DaemonClient
import messages_pb2


req = messages_pb2.PingRequest()
req.params.msg = "python"
req.params.display = True

client = DaemonClient("http://127.0.0.1:8080")
client.ping(req)
client.ping(req)
