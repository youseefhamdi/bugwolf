// ## Source: bugwolf Phase 3.1 — ANTLR-style GraphQL grammar
// ## Source: GraphQL October 2021 spec (https://spec.graphql.org/October2021/)
// ## License: bugwolf-MIT + GraphQL Foundation (spec)
// ## Schema: bugwolf-fuzz-v1
//
// Minimal ANTLR4 grammar for GraphQL queries.  Covers document,
// operation definitions, selection sets, arguments and values.

grammar graphql;

document         : definition+ ;
definition       : executable_definition | type_system_definition ;
executable_definition : operation_definition | fragment_definition ;

operation_definition
    : operation_type operation_name? variable_definitions? directives? selection_set
    | selection_set
    ;

operation_type   : 'query' | 'mutation' | 'subscription' ;
operation_name   : name ;

variable_definitions : '(' variable_definition+ ')' ;
variable_definition  : variable ':' type default_value? directives? ;
variable             : '$' name ;
default_value        : '=' value ;

selection_set     : '{' selection+ '}' ;
selection         : field | fragment_spread | inline_fragment ;
field             : alias? field_name arguments? directives? selection_set? ;
alias             : name ':' ;
field_name        : name ;
arguments         : '(' argument+ ')' ;
argument          : name ':' value ;

fragment_definition : 'fragment' fragment_name 'on' type directives? selection_set ;
fragment_name      : name ;
fragment_spread    : '...' fragment_name directives? ;
inline_fragment    : '...' 'on'? type directives? selection_set ;

type              : named_type | list_type | non_null_type ;
named_type        : name ;
list_type         : '[' type ']' ;
non_null_type     : named_type '!' | list_type '!' ;

value             : variable | int_value | float_value | string_value | boolean_value | null_value | enum_value | list_value | object_value ;
int_value         : '-'? digit+ ;
float_value       : '-'? digit+ '.' digit+ ( exponent )? ;
string_value      : '"' string_char* '"' | '"""' block_char* '"""' ;
boolean_value     : 'true' | 'false' ;
null_value        : 'null' ;
enum_value        : name (but not a keyword);
list_value        : '[' value* ']' ;
object_value      : '{' object_field* '}' ;
object_field      : name ':' value ;

directives        : directive+ ;
directive         : '@' name arguments? ;

name              : name_start name_continue* ;
name_start        : alpha | '_' ;
name_continue     : alpha | digit | '_' ;

digit             : '0'..'9' ;
alpha             : 'A'..'Z' | 'a'..'z' ;

string_char       : unescaped | escaped ;
unescaped         : '\u0020'..'\u0021' | '\u0023'..'\u005B' | '\u005D'..'\u007E' ;
escaped           : '\\' ( '"' | '\\' | '/' | 'b' | 'f' | 'n' | 'r' | 't' | 'u' hex4 ) ;
block_char        : '\u000A' | '\u000D' | unescaped | escaped ;
hex4              : hex hex hex hex ;
hex               : digit | 'A'..'F' | 'a'..'f' ;

exponent          : ( 'e' | 'E' ) ( '+' | '-' )? digit+ ;
