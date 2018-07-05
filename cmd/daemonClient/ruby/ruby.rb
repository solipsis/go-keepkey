
require_relative 'messages_pb.rb'
require_relative 'messages_twirp.rb'

client = Solipsis::Gkk::Daemon::DaemonClient.new("http://127.0.0.1:8080/twirp")

#req = Solipsis::Gkk::Daemon::PingRequest.new(msg: "ruby")
params = Solipsis::Gkk::Daemon::PingParams.new(msg: "ruby", display: true)
puts "start"
resp = client.ping(Solipsis::Gkk::Daemon::PingRequest.new(params: params))
if resp.error
	puts resp.error
end
puts "mid"
resp = client.ping(Solipsis::Gkk::Daemon::PingRequest.new(params: params))
if resp.error
	puts resp.error
end
puts "done"
