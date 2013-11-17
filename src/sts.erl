%%%-------------------------------------------------------------------
%%% @author abc
%%% @copyright (C) 2013, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 13. Nov 2013 11:50 PM
%%%-------------------------------------------------------------------
-module(sts).
-behavior(gen_server).
-export([init/1, handle_info/2, handle_call/3, terminate/2, handle_cast/2, code_change/3]).
-include("records.erl").

-record(targetRec, {id, name, certificate}).
-record(userRec, {id, name, email, authenticator}).
-record(authenticatorRec, {remote, certificate}).
-record(stsState, {id, certificate, users, targets}).

init({StsID, Certificate}) -> {ok,#stsState{id = StsID, certificate = Certificate, users = dict:new(), targets = dict:new()}}.

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

handle_call({registerTarget, Name, Certificate}, _From, State) ->
  try
    Exists = target_exists(State,Name, Certificate),
    if Exists == true -> throw(duplicate_target);
       true ->
        TargetID = uuid:to_string(uuid:v4()),
        Target = #targetRec{id = TargetID, name = Name, certificate = Certificate},
        NewState = new_target(State, Target),
        {reply,{ok,TargetID},NewState}
    end
  catch Exception ->
    {reply,{false, Exception}, State}
  end;

handle_call({registerUser, Name, Email, AuthenticatorRemote, AuthPublicKey}, _From, State) ->
  io:format("STS: Registering user: ~p~n",[Name]),
  UserID = uuid:to_string(uuid:v4()),
  User = #userRec{authenticator = #authenticatorRec{remote = AuthenticatorRemote, certificate = AuthPublicKey}, id = UserID, name = Name, email = Email},
  NewState = State#stsState{users = dict:store(Name, User, State#stsState.users)},
  {reply, {ok, UserID}, NewState};

handle_call({verify, SignedMsg}, _From, State) ->
  io:format("STS: Verifying: ~p~n",[SignedMsg]),
  try
    verify_target_signature(State, SignedMsg#target2sts.targetID, SignedMsg),
    TargetName = get_target_name(State, SignedMsg#target2sts.targetID),
    confirm_user(State, SignedMsg#target2sts.requestID, SignedMsg#target2sts.userName, TargetName, SignedMsg#target2sts.reason),
    io:format("STS: Verified: ~p~n",[SignedMsg]),
    {reply, auth_security:sign([confirmed]), State}
  catch _ ->
    io:format("STS: Denied: ~p~n",[SignedMsg]),
    {reply, auth_security:sign([denied]), State}
  end;

handle_call(Msg, _From, State) ->
  io:format("Unexpected message: ~p~n",[Msg]),
  {reply, false, State}.

new_target(State, TargetRec) ->
  State#stsState{targets = dict:store(TargetRec#targetRec.id, TargetRec, State#stsState.targets)}.

verify_target_signature(State, TargetID, SignedMsg) ->
  TargetCertificate = lookup_target_certificate(State, TargetID),
  % Last element is signature
  auth_security:verify_signature(utils:signedRecord2list(SignedMsg), element(tuple_size(SignedMsg), SignedMsg), TargetCertificate).

lookup_target_certificate(State, TargetID) ->
  Target = lookup_target(State, TargetID),
  Target#targetRec.certificate.

get_target_name(State, TargetID) ->
  Target = lookup_target(State, TargetID),
  Target#targetRec.name.

confirm_user(State, RequestID, Username, TargetName, Reason) ->
  Authenticator = user_authenticator(State, Username),
  Msg = #sts2authenticator{reason = Reason, requestID = RequestID, stsID = State#stsState.id, targetName = TargetName, userName = Username},
  SignedMsg = Msg#sts2authenticator{stsSignature = auth_security:signature(Msg, State#stsState.certificate)},
  Reply = gen_server:call(Authenticator#authenticatorRec.remote, {confirm, SignedMsg}),
  verify_authenticator_signature(State, Reply, Authenticator),
  case {Reply#authenticator2sts.requestID, Reply#authenticator2sts.decision} of
    {RequestID, confirmed} -> ok;
    {RequestID, denied} -> throw(denied)
  end.

verify_authenticator_signature(_State, Msg, Authenticator) ->
  auth_security:verify_signature(Msg, Msg#authenticator2sts.authenticatorSignature, Authenticator#authenticatorRec.certificate).

user_authenticator(State, Username) ->
  User = lookup_user(State, Username),
  User#userRec.authenticator.

lookup_user(State, Username) ->
  dict:fetch(Username, State#stsState.users).

lookup_target(State, TargetID) ->
  dict:fetch(TargetID, State#stsState.targets).

target_exists(State, TargetName, Certificate) ->
  Matcher = fun (_Key, Value, Acc) ->
      Acc == true orelse string:to_lower(Value#targetRec.name) == string:to_lower(TargetName) orelse Value#targetRec.certificate == Certificate
  end,
  dict:fold(Matcher, false, State#stsState.targets).



