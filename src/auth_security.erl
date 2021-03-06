%%%-------------------------------------------------------------------
%%% @author Denis Mikhalkin
%%% @copyright (C) 2013, Denis Mikhalkin
%%% @doc
%%%
%%% @end
%%% Created : 14. Nov 2013 10:33 PM
%%%-------------------------------------------------------------------
-module(auth_security).

%% API
-export([verify_signature/2, sign/2, verify_password/2]).

verify_password(PasswordGiven, PasswordProvided) ->
  PasswordGiven = PasswordProvided.

%% Msg can be either a record or a list.
%% The last element in tuple may or may not contain the signature value (may be empty). If it contains signature it should be ignored
%% The last element of a list is signature
%% Throws exception if signature is invalid
verify_signature(Msg, Certificate) when is_tuple(Msg) ->
  verify_signature(tuple_to_list(Msg), Certificate);
verify_signature(Msg, Certificate) when is_list(Msg) ->
  Signature = lists:last(Msg),
  Body = lists:sublist(Msg, length(Msg)-1),
  verify_signature(Body, Signature, Certificate).
verify_signature(_Body, Signature, Certificate) -> % Throws
  % TODO Implement actual signature validation
  {Name, publicKey} = Certificate,
  Signature = {signature, {Name, privateKey}}.


sign(Msg, {_Name, privateKey} = Certificate) when is_list(Msg) ->
  % TODO Implement actual signature generation
  Msg ++ [{signature, Certificate}];
sign(Msg, {_Name, privateKey} = Certificate) when is_tuple(Msg) ->
  setelement(tuple_size(Msg), Msg, {signature, Certificate}).