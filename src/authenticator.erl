%%%-------------------------------------------------------------------
%%% @author abc
%%% @copyright (C) 2013, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 13. Nov 2013 11:51 PM
%%%-------------------------------------------------------------------
-module(authenticator).
-behavior(gen_server).
-export([init/1, handle_info/2, handle_call/3, terminate/2, handle_cast/2, code_change/3]).

init(_Args) -> {ok, _Args}.

handle_info(Msg, State) ->
  io:format("Unexpected message: ~p~n",[Msg]),
  {noreply, State}.

handle_cast(stop, State) ->
  {stop, normal, State}.

terminate(normal, _State) ->
  io:format("Stopping the server~n"),
  ok.

code_change(_OldVsn, State, _Extra) ->
  {ok, State}.

handle_call(terminate, _From, State) ->
  {stop, normal, ok, State};


handle_call({confirm,Claims}, _From, State) ->
  io:format("Authenticator: confirming claims ~p~n", [Claims]),
  try
    auth_security:verify_signature(Claims,sts_token(State)),
    Username = auth_security:extract_claim(Claims,user),
    Username = logged_in_user(State),
    Target = auth_security:extract_claim(Claims,target),
    io:format("Authorize user ~p access to ~p?",[Username,Target]),
    Input = element(1, State),
    if Input == "y" orelse Input == "Y" -> {reply, auth_security:sign([{confirmed,Claims}]), State};
       true -> throw(denied)
    end
  catch _ ->
    io:format("Authenticator: Denied access for claims ~p~n", [Claims]),
    {reply, auth_security:sign([{denied,Claims}]), State}
  end;

handle_call(Msg, _From, State) ->
  io:format("Unexpected message: ~p~n",[Msg]),
  {reply, false, State}.

logged_in_user(_State) -> "Denis".
sts_token(_State) -> valid_sts_token.