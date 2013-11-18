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

-include("records.erl").

-record(authenticatorRec, {loggedInUser, privateKey, stsPublicKey, dummyInput}).

init({PrivateKey, StsPublicKey, DummyInput}) -> {ok, #authenticatorRec{privateKey = PrivateKey, stsPublicKey = StsPublicKey, dummyInput = DummyInput}}.

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

% TODO Implement validation
handle_call({loginUser, Username}, _From, State) ->
  NewState = State#authenticatorRec{loggedInUser = Username},
  {reply, ok, NewState};

handle_call({confirm, Msg}, _From, State) ->
  io:format("Authenticator: confirming ~p~n", [Msg]),
  try
    auth_security:verify_signature(Msg, get_sts_public_key(State)),
    Username = Msg#sts2authenticator.userName,
    Username = logged_in_user(State), % Fails if not the same
    Target = Msg#sts2authenticator.targetName,
    Reason = Msg#sts2authenticator.reason,
    io:format("Authorize user ~p access to ~p for ~p~n", [Username, Target, Reason]),
    Input = State#authenticatorRec.dummyInput,
    if Input == "y" orelse Input == "Y" ->
        Reply = #authenticator2sts{decision = confirmed, requestID = Msg#sts2authenticator.requestID},
        SignedReply = auth_security:sign(Reply, get_private_key(State)),
        {reply, SignedReply, State};
      true -> throw(denied)
    end
  catch _ ->
    io:format("Authenticator: Denied access ~p~n", [Msg]),
    Reply2 = #authenticator2sts{decision = denied, requestID = Msg#sts2authenticator.requestID},
    SignedReply2 = auth_security:sign(Reply2, get_private_key(State)),
    {reply, SignedReply2, State}
  end;

handle_call(Msg, _From, State) ->
  io:format("Unexpected message: ~p~n",[Msg]),
  {reply, false, State}.

logged_in_user(State)     -> State#authenticatorRec.loggedInUser.
get_private_key(State)    -> State#authenticatorRec.privateKey.
get_sts_public_key(State) -> State#authenticatorRec.stsPublicKey.