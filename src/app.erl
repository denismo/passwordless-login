%%%-------------------------------------------------------------------
%%% @author abc
%%% @copyright (C) 2013, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 13. Nov 2013 11:34 PM
%%%-------------------------------------------------------------------
-module(app).

%% API
-export([start_app/1, test_app/1]).

start_app(DummyInput) ->
  code:ensure_loaded(auth_security),
  code:ensure_loaded(user_server),
  code:ensure_loaded(target),
  code:ensure_loaded(sts),
  code:ensure_loaded(authenticator),
  gen_server:start_link({local, target_server}, target, {targetID, targetPrivateKey},[]),
  gen_server:start_link({local, user_server}, user_server, [],[]),
  gen_server:start_link({local, sts_server}, sts, {"STS", stsPrivateKey},[]),
  gen_server:start_link({local, authenticator_server}, authenticator, {authPrivateKey, stsPublicKey, DummyInput},[]).

test_app(DummyInput) ->
  start_app(DummyInput),
  {ok, TargetID} = gen_server:call(sts_server, {registerTarget, "Mail", targetPrivateKey}),
  gen_server:call(target_server, {newTargetID, TargetID}),
  gen_server:call(sts_server, {registerUser, "Denis", "denismo@yahoo.com", authenticator_server, authPublicKey}),
  gen_server:call(authenticator_server, {loginUser, "Denis"}),
  gen_server:call(user_server,{start,target_server,"Denis"}).



