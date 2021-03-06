%%%-------------------------------------------------------------------
%%% @author Denis Mikhalkin
%%% @copyright (C) 2013, Denis Mikhalkin
%%% @doc
%%%
%%% @end
%%% Created : 13. Nov 2013 11:50 PM
%%%-------------------------------------------------------------------
-module(user_server).
-behavior(gen_server).
-export([init/1, handle_info/2, handle_call/3, terminate/2, handle_cast/2,code_change/3]).
-include("records.erl").

init(_Args) -> {ok,[]}.

%% Testing helper - creates the first request which simulates the user's activity on the target site
handle_call({start,Target,Username}, _From, State) ->
  io:format("User was asked to start~n"),
  Reply = gen_server:call(Target, {login, Username}),
  {reply, Reply, State};

handle_call(terminate, _From, State) ->
  {stop, normal, ok, State};
handle_call(Msg, _From, State) ->
  io:format("Unexpected message: ~p~n",[Msg]),
  {reply, false, State}.

handle_cast(stop, State) ->
  {stop, normal, State}.

terminate(normal, _State) ->
  io:format("Stopping the target server~n"),
  ok.

handle_info(Msg, State) ->
  io:format("Unexpected message: ~p~n",[Msg]),
  {noreply, State}.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

