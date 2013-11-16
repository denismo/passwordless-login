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
-export([start_app/0]).

start_app() ->
  code:ensure_loaded(auth_security),
  code:ensure_loaded(user_server),
  code:ensure_loaded(target),
  code:ensure_loaded(sts),
  code:ensure_loaded(authenticator),
  gen_server:start_link({local, target_server}, target, [],[]),
  gen_server:start_link({local, user_server}, user_server, [],[]),
  gen_server:start_link({local, sts_server}, sts, [],[]),
  gen_server:start_link({local, authenticator_server}, authenticator, {"Y"},[]).

