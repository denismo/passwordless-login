%%%-------------------------------------------------------------------
%%% @author Denis Mikhalkin
%%% @copyright (C) 2013, Denis Mikhalkin
%%% @doc
%%%
%%% @end
%%% Created : 13. Nov 2013 11:50 PM
%%%-------------------------------------------------------------------
-module(trust).
-behavior(gen_server).
-export([init/1, handle_info/2, handle_call/3, terminate/2, handle_cast/2, code_change/3]).
-include("records.erl").

-record(targetRec, {id, name, certificate}).
-record(userRec, {name, password, email, authenticator}).
-record(authenticatorRec, {remote, certificate}).
-record(trustState, {id, certificate, users, targets}).

init({TrustID, Certificate}) -> {ok,#trustState{id = TrustID, certificate = Certificate, users = dict:new(), targets = dict:new()}}.

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

%% Request to register target system on the trust server.
%% The system should be unique with regards to the combination of {name, certificate).
%% The request is sent by a target.
handle_call({registerTarget, Msg}, _From, State) ->
  try
    auth_security:verify_signature(Msg, Msg#target2trustRegister.certificate),
    Name = Msg#target2trustRegister.name, Certificate = Msg#target2trustRegister.certificate,
    Exists = target_exists(State,Name,Certificate),
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

%% Request to register a new user on the trust system.
%% This is where user creates an account so that he can later be authorized on target websites via this trust server.
%% The registration is assumed to happen via a web UI (perhaps also via the mobile authenticator app).
handle_call({registerUser, Username, Password, Email}, _From, State) ->
  io:format("Trust: Registering user: ~p~n",[Username]),
  verify_user_does_not_exist(State, Username),
  User = #userRec{name = Username, email = Email, password = Password}, % TODO No, we are not planning to store clear text passwords - this is a placeholder!
  NewState = update_user(State, Username, User),
  {reply, ok, NewState};

%% Request to login the user on the authenticator app.
%% Verifies that the user is registered, the credentials match, and stores the association between
%% the user and the authenticator that is going to be used for future authorization requests from target.
%% The request is sent by the authenticator app.
handle_call({loginUser, Msg}, From, State) ->
  io:format("Trust: User ~p login from ~p~n", [Msg#authenticator2trustLogin.userName, From]),
  User = lookup_user(State, Msg#authenticator2trustLogin.userName),
  verify_user_no_authenticator(User),
  auth_security:verify_password(User#userRec.password, Msg#authenticator2trustLogin.password),
  {FromPid, _} = From,
  NewUser = User#userRec{authenticator = #authenticatorRec{remote = FromPid, certificate = Msg#authenticator2trustLogin.authCertificate}},
  NewState = update_user(State, Msg#authenticator2trustLogin.userName, NewUser),
  {reply, auth_security:sign({ok, invalid}, State#trustState.certificate), NewState};

%% Message from target - request to verify the user who tries to access the target system
%% Contact's the user's authenticator for authorization
handle_call({verify, SignedMsg}, _From, State) ->
  io:format("Trust: Confirming: ~p~n",[SignedMsg]),
  try
    verify_target_signature(State, SignedMsg#target2trust.targetID, SignedMsg),
    TargetName = get_target_name(State, SignedMsg#target2trust.targetID),
    confirm_user(State, SignedMsg#target2trust.requestID, SignedMsg#target2trust.userName, TargetName, SignedMsg#target2trust.reason),
    io:format("Trust: Confirmed: ~p~n",[SignedMsg]),
    {reply, auth_security:sign({confirmed, invalid}, State#trustState.certificate), State}
  catch _ ->
    io:format("Trust: Denied: ~p~n",[SignedMsg]),
    {reply, auth_security:sign({denied, invalid}, State#trustState.certificate), State}
  end;

handle_call(Msg, _From, State) ->
  io:format("Unexpected message: ~p~n",[Msg]),
  {reply, false, State}.



%% ====================================== Private functions ======================================

verify_user_no_authenticator(User) ->
  if User#userRec.authenticator /= undefined -> throw (already_logged_in);
     true -> ok
  end.

verify_user_does_not_exist(State, Username) ->
  case dict:find(Username, State#trustState.users) of
    {ok, _Value} -> throw (exists);
    _ -> ok
  end.

new_target(State, TargetRec) ->
  State#trustState{targets = dict:store(TargetRec#targetRec.id, TargetRec, State#trustState.targets)}.

verify_target_signature(State, TargetID, SignedMsg) ->
  TargetCertificate = lookup_target_certificate(State, TargetID),
  % Last element is signature
  auth_security:verify_signature(SignedMsg, TargetCertificate).

lookup_target_certificate(State, TargetID) ->
  Target = lookup_target(State, TargetID),
  Target#targetRec.certificate.

get_target_name(State, TargetID) ->
  Target = lookup_target(State, TargetID),
  Target#targetRec.name.

confirm_user(State, RequestID, Username, TargetName, Reason) ->
  Authenticator = user_authenticator(State, Username),
  Msg = #trust2authenticator{reason = Reason, requestID = RequestID, trustID = State#trustState.id, targetName = TargetName, userName = Username},
  SignedMsg = auth_security:sign(Msg, State#trustState.certificate),
  Reply = gen_server:call(Authenticator#authenticatorRec.remote, {confirm, SignedMsg}),
  io:format("Trust: authenticator reply: ~p~n", [Reply]),
  verify_authenticator_signature(State, Reply, Authenticator),
  case {Reply#authenticator2trust.requestID, Reply#authenticator2trust.decision} of
    {RequestID, confirmed} -> ok;
    {RequestID, denied} -> throw(denied)
  end.

verify_authenticator_signature(_State, Msg, Authenticator) ->
  auth_security:verify_signature(Msg, Authenticator#authenticatorRec.certificate).

user_authenticator(State, Username) ->
  User = lookup_user(State, Username),
  User#userRec.authenticator.

lookup_user(State, Username) ->
  dict:fetch(Username, State#trustState.users).

update_user(State, Username, User) ->
  State#trustState{users = dict:store(Username, User, State#trustState.users)}.

lookup_target(State, TargetID) ->
  dict:fetch(TargetID, State#trustState.targets).

target_exists(State, TargetName, Certificate) ->
  Matcher = fun (_Key, Value, Acc) ->
      Acc == true orelse string:to_lower(Value#targetRec.name) == string:to_lower(TargetName) orelse Value#targetRec.certificate == Certificate
  end,
  dict:fold(Matcher, false, State#trustState.targets).
