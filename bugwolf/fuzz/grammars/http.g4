// ## Source: bugwolf Phase 3.1 — ANTLR-style HTTP grammar
// ## Source: RFC 9110 (HTTP semantics) + RFC 9112 (HTTP/1.1 message syntax)
// ## License: bugwolf-MIT + IETF Trust (RFC text)
// ## Schema: bugwolf-fuzz-v1
//
// Minimal ANTLR4 grammar for HTTP/1.1 request messages.  This grammar
// is consumed by bugwolf.fuzz.grammar_based.load_grammar; the EBNF
// subset implemented there covers everything below.

grammar http;

request     : method SP request_target SP http_version CRLF header* CRLF body? ;
response    : http_version SP status_code SP reason_phrase CRLF header* CRLF body? ;

method      : 'GET' | 'POST' | 'PUT' | 'DELETE' | 'PATCH' | 'HEAD' | 'OPTIONS' ;
request_target: '/' path_segments? ( '?' query_string )? ;
path_segments: path_segment ( '/' path_segment )* ;
path_segment: path_char+ ;
path_char   : alpha | digit | '_' | '-' | '.' | '~' | '!' | '$' | '&' | '\'' | '(' | ')' | '*' | '+' | ',' | ';' | '=' | ':' | '@' ;
query_string: query_pair ( '&' query_pair )* ;
query_pair  : query_key ( '=' query_value )? ;
query_key   : alpha | digit | '_' | '-' | '.' ;
query_value : query_char+ ;
query_char  : path_char | '%' ;

http_version: 'HTTP/' digit '.' digit ;
status_code : digit digit digit ;
reason_phrase: reason_char+ ;
reason_char : alpha | digit | ' ' | '-' | '.' ;

header      : header_name ':' OWS header_value OWS CRLF ;
header_name : token ;
header_value: header_value_char+ ;
header_value_char: alpha | digit | ' ' | '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '.' | '^' | '_' | '`' | '|' | '~' ;

token       : token_char+ ;
token_char  : alpha | digit | '!' | '#' | '$' | '%' | '&' | '\'' | '*' | '+' | '-' | '.' | '^' | '_' | '`' | '|' | '~' ;

body        : body_char* ;
body_char   : any_char ;

alpha       : 'A'..'Z' | 'a'..'z' ;
digit       : '0'..'9' ;
SP          : ' ' ;
CRLF        : '\r\n' ;
OWS         : ( ' ' | '\t' )* ;
any_char    : '\u0000'..'\u007F' ;
