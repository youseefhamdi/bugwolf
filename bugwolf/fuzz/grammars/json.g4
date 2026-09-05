// ## Source: bugwolf Phase 3.1 — ANTLR-style JSON grammar
// ## Source: RFC 8259 (The JavaScript Object Notation Data Interchange Format)
// ## License: bugwolf-MIT + IETF Trust
// ## Schema: bugwolf-fuzz-v1
//
// Minimal ANTLR4 grammar for RFC 8259 JSON.  Used by the
// grammar-based fuzzer to drive HTTP/JSON APIs.

grammar json;

json           : value ;
value          : object | array | string | number | 'true' | 'false' | 'null' ;

object         : '{' ( pair ( ',' pair )* )? '}' ;
pair           : string ':' value ;

array          : '[' ( value ( ',' value )* )? ']' ;

string         : '"' chars* '"' ;
chars          : char | escape ;
char           : '\u0020'..'\u0021' | '\u0023'..'\u005B' | '\u005D'..'\u007E' ;
escape         : '\\' ( '"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't' | 'u' hex4 ) ;

number         : int frac? exp? ;
int            : '-'? ( '0' | digit1_9 digit* ) ;
frac           : '.' digit+ ;
exp            : ( 'e' | 'E' ) ( '+' | '-' )? digit+ ;

digit1_9       : '1'..'9' ;
digit          : '0'..'9' ;
hex4           : hex hex hex hex ;
hex            : digit | 'A'..'F' | 'a'..'f' ;
