// ## Source: bugwolf Phase 3.1 — ANTLR-style gRPC grammar
// ## Source: gRPC over HTTP/2 framing (https://github.com/grpc/grpc/blob/master/doc/PROTOCOL-HTTP2.md)
// ## License: bugwolf-MIT
// ## Schema: bugwolf-fuzz-v1
//
// Minimal ANTLR4 grammar for gRPC request messages framed over
// HTTP/2.  The grammar covers the HTTP/2 HEADERS+DATA frames plus
// the 5-byte gRPC length-prefixed message framing.

grammar grpc;

grpc_request   : http2_headers http2_data* ;
grpc_response  : http2_headers http2_data* ;

http2_headers  : magic http2_header* empty_header CRLF ;
magic          : 'PRI' SP '*' SP 'HTTP/2.0' CRLF ;
http2_header   : header_name ':' OWS header_value OWS CRLF ;
empty_header   : ;

header_name    : token ;
header_value   : header_value_char+ ;
header_value_char : alpha | digit | ' ' | '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '.' | '^' | '_' | '`' | '|' | '~' ;

http2_data     : data_frame_header grpc_message ;
data_frame_header : grpc_compressed byte32 ;
grpc_compressed : '0' | '1' ;
byte32         : byte byte byte byte ;
byte           : '\u0000'..'\u00FF' ;

grpc_message   : length_prefix message_payload ;
length_prefix  : byte32 ;
message_payload: payload_byte* ;
payload_byte   : '\u0000'..'\u00FF' ;

token          : token_char+ ;
token_char     : alpha | digit | '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '.' | '^' | '_' | '`' | '|' | '~' ;

alpha          : 'A'..'Z' | 'a'..'z' ;
digit          : '0'..'9' ;
SP             : ' ' ;
CRLF           : '\r\n' ;
OWS            : ( ' ' | '\t' )* ;
