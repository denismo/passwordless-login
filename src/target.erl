%%%-------------------------------------------------------------------
%%% @author abc
%%% @copyright (C) 2013, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 13. Nov 2013 11:36 PM
%%%-------------------------------------------------------------------
-module(target).
-behavior(gen_server).
-export([init/1, handle_info/2, handle_call/3, terminate/2, handle_cast/2,code_change/3]).
-include("records.erl").

-record(targetState, {targetID,privateCert}).

init({TargetID, Certificate}) ->
  {ok,#targetState{privateCert = Certificate, targetID = TargetID}}.

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
handle_call({login,Username}, _From, State) ->
  io:format("User ~p is loging in~n", [Username]),
  Msg = #target2sts{reason = "User login",
                    requestID = uuid:to_string(uuid:v4()),
                    targetID = State#targetState.targetID,
                    userName = Username},
  Signature = auth_security:signature(Msg, State#targetState.privateCert),
  SignedMsg = Msg#target2sts{targetsSignature = Signature},
  Reply = gen_server:call(sts_server, {verify, SignedMsg}),
  % TODO Verify STS signature
  {reply, Reply, State};

handle_call({newTargetID, TargetID}, _From, State) ->
  NewState = State#targetState{targetID = TargetID},
  {reply,ok,NewState};

handle_call(Msg, _From, State) ->
  io:format("Unexpected message: ~p~n",[Msg]),
  {reply, false, State}.

