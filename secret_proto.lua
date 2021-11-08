-- Author  : Peter Zdravecký (xzdrav00)
-- Version : 0.1
-- Date 2021-11-07

secret_protocol = Proto("MNT","Secret Protocol")

type      		= ProtoField.string("mnt.type"      , "type")
datalen     	= ProtoField.int32( "mnt.datalen"   , "datalen"   , base.DEC)
seq          	= ProtoField.int32( "mnt.seq"       , "seq"       , base.DEC)
client_id       = ProtoField.int32( "mnt.client_id" , "client_id" , base.DEC)
data 			= ProtoField.bytes( "mnt.data" 		, "data")

secret_protocol.fields = { type, datalen, seq, client_id,data }

local type_enum = {
	[0] = "Init transfer",
	[1] = "Data transfer",
	[2] = "End transfer"
  }

function secret_protocol.dissector(buffer, pkt, tree)
	
	length = buffer:len()
	if length == 0 then return end

	-- Start byte for secret proto
	local start = 0
	
	-- IPV4 START--
	if length < 45 then return end
	if buffer(42,3):string() == "MNT" then start = 42 end
	-- IPV4 END--

	-- IPV6 START--
	if start == 0 then
		if length < 65 then return end
		if buffer(62,3):string() == "MNT" then start = 62 end
	end
	-- IPV6 END --
	if start == 0 then return end

	pkt.cols.protocol = secret_protocol.name
	local subtree = tree:add(secret_protocol, buffer(), "Secret Protocol")
	subtree:add_le(type		 ,type_enum[buffer(start+4,4):le_int()])
	subtree:add_le(datalen	 ,buffer(start+8,4):le_int())
	subtree:add_le(seq		 ,buffer(start+12,4):le_int())
	subtree:add_le(client_id ,buffer(start+16,4):le_int())
	subtree:add_le(data		 ,buffer(start+20))

end

register_postdissector(secret_protocol)
