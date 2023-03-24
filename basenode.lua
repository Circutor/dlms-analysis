-- 
-- Lua dissector for DLMS wrapper that transmit data over TCP (used in SCADA systems)
-- The payload is later interpreted as DLMS/COSEM (requires dlms.lua dissector)
--
-- Version 1.0
-- Last update: 28th March 2018
--
-- developed as a part of IRONSTONE research project
-- 
-- (c) Petr Matousek, FIT BUT, Czech Republic, 2018
-- Contact:  matousp@fit.vutbr.cz

-- Declare the protocol
bn_proto = Proto("BaseNode","Base Node over TCP")

local BNType = {
	[1] = "New device notification",
	[2] = "Remove device notification",
	[3] = "Start reporting meters",
	[4] = "Delete meters",
	[5] = "Enable auto close",
	[6] = "Disable auto close",
}

local Type = ProtoField.uint8("bn.type","Type",base.HEX,BNType)

bn_proto.fields = {Type}

-- Create a simple dissection function
function bn_proto.dissector(buffer, pinfo, tree)

   -- Create the bn tree
    local t_bn = tree:add(bn_proto, buffer())
    local frame_len = buffer:len()
    local offset = 0
    
    t_bn:add(Type, buffer(0,1))
    
    local bnType = buffer(0,1):uint()
    
    pinfo.cols['info'] = BNType[bnType]
end
