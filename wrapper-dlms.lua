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
wrapper_proto = Proto("DLMS-Wrapper","DLMS Wrapper over TCP")

-- The offset of the wrapper header that will be skipped 
local WRAPPER_HEADER=8 

local Version = ProtoField.uint16("wrapper.version","Version",base.HEX)
local Source = ProtoField.uint16("wrapper.src","Source",base.HEX)
local Destination = ProtoField.uint16("wrapper.dest","Destination",base.HEX)

wrapper_proto.fields = {Version, Source, Destination}

-- Create a simple dissection function
function wrapper_proto.dissector(buffer, pinfo, tree)

   -- Create the wrapper tree
    local t_wrapper = tree:add(wrapper_proto, buffer())
    local frame_len = buffer:len()
    local offset = 0

    -- Skip the uninterpreted wrapper header data
    t_wrapper:add(Version, buffer(0,2))
    t_wrapper:add(Source, buffer(2,2))
    t_wrapper:add(Destination, buffer(4,2))
    
    local source = buffer(2,2):uint()
    local destination = buffer(4,2):uint()
    
     if source == 0 or destination == 0 then
		-- Call Base Node dissector on the rest of the buffer
		local new_buffer = buffer(offset+WRAPPER_HEADER,frame_len-8)
		local dissector = Dissector.get("basenode")
		dissector:call(new_buffer:tvb(),pinfo,tree)
		pinfo.cols['protocol'] = "BaseNode"
	else
		-- Call DLMS dissector on the rest of the buffer
		local new_buffer = buffer(offset+WRAPPER_HEADER,frame_len-8)
		local dissector = Dissector.get("dlms")
		dissector:call(new_buffer:tvb(),pinfo,tree)
		pinfo.cols['protocol'] = "DLMS"
	end
end

-- load the tcp port table
tcp_table = DissectorTable.get("tcp.port")
-- register the protocol to ports 5025, 4063, 4059, 40000 (should be changed based on your data)
tcp_table:add(5025, wrapper_proto)
tcp_table:add(4063, wrapper_proto)
tcp_table:add(4059, wrapper_proto)
tcp_table:add(40000, wrapper_proto)
