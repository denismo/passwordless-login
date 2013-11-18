%%%-------------------------------------------------------------------
%%% @author abc
%%% @copyright (C) 2013, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 13. Nov 2013 11:34 PM
%%%-------------------------------------------------------------------
-module(app).
-vsn(1.1).

%% API
-export([start_app/1, test_app/1]).

start_app(DummyInput) ->
  code:ensure_loaded(auth_security),
  code:ensure_loaded(user_server),
  code:ensure_loaded(target),
  code:ensure_loaded(trust),
  code:ensure_loaded(authenticator),
  gen_server:start_link({local, target_server}, target, {targetID, {target, privateKey}, {trust, publicKey}},[]),
  gen_server:start_link({local, user_server}, user_server, [],[]),
  gen_server:start_link({local, trust_server}, trust, {"Trust Server", {trust, privateKey}},[]),
  gen_server:start_link({local, authenticator_server}, authenticator, {{auth, privateKey}, {trust, publicKey}, DummyInput},[]).

test_app(DummyInput) ->
  start_app(DummyInput),
  {ok, TargetID} = gen_server:call(trust_server, {registerTarget, "Mail", {target, publicKey}}),
  gen_server:call(target_server, {newTargetID, TargetID}),
  gen_server:call(trust_server, {registerUser, "Denis", "denismo@yahoo.com", authenticator_server, {auth, publicKey}}),
  gen_server:call(authenticator_server, {loginUser, "Denis"}),
  gen_server:call(user_server,{start,target_server,"Denis"}).



