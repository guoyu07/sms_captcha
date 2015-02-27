json.array!(@msgs) do |msg|
  json.extract! msg, :id, :vpnip, :vpnmac, :phone, :sms
  json.url msg_url(msg, format: :json)
end
