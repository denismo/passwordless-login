%%%-------------------------------------------------------------------
%%% @author abc
%%% @copyright (C) 2013, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 14. Nov 2013 10:33 PM
%%%-------------------------------------------------------------------
-module(auth_security).

%% API
-export([extract_claim/2, verify_signature/2, sign/1]).

extract_claim([Claim|T],Name) ->
  case Claim of
    {claim,Name,Target} -> Target;
    _ -> extract_claim(T,Name)
  end;
extract_claim([],_Name) -> invalid.

verify_signature(_Claims,_Token) ->
  true.

sign(Claims) ->
  % TODO Generate unique signature (At last matching target - using target certificate)
  Claims ++ [{signature,valid}].