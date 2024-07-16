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
	[7] = "Unregister meters",
	[8] = "Phase result",
	[9] = "Phase request",
}

local Type = ProtoField.uint8("bn.type","Type",base.HEX,BNType)
local DeviceID = ProtoField.uint16("bn.deviceID","DeviceID",base.HEX)
local EUI48 = ProtoField.string("bn.eui48","EUI48")

bn_proto.fields = {Type, DeviceID, EUI48}

-- Create a simple dissection function
function bn_proto.dissector(buffer, pinfo, tree)

   -- Create the bn tree
    local t_bn = tree:add(bn_proto, buffer())
    local frame_len = buffer:len()
    local offset = 0
    
    t_bn:add(Type, buffer(0,1))
    
    local bnType = buffer(0,1):uint()
    
    if bnType == 8 or bnType == 9 then
        local instance = buffer(1,6)
        local eui48 = string.format("%02x:%02x:%02x:%02x:%02x:%02x",instance(0,1):uint(),instance(1,1):uint(),instance(2,1):uint(),instance(3,1):uint(),instance(4,1):uint(),instance(5,1):uint())
        
        t_bn:add(EUI48, eui48)
        
        pinfo.cols['info'] = BNType[bnType].." EUI48="..eui48
    else
        pinfo.cols['info'] = BNType[bnType]
    end
    
    if bnType == 1 or bnType == 2 or bnType == 4 or bnType == 5 or bnType == 6 or bnType == 7 then
    	t_prime:add(LNID, buffer(1,2))
    end
end
