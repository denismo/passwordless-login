%%%-------------------------------------------------------------------
%%% @author abc
%%% @copyright (C) 2013, <COMPANY>
%%% @doc
%%%
%%% @end
%%% Created : 14. Nov 2013 10:07 PM
%%%-------------------------------------------------------------------

%% API
-record(target2trust,{targetID,userName, reason, requestID, targetsSignature}).
-record(trust2authenticator, {targetName, requestID, userName, reason, trustID, trustSignature}).
-record(authenticator2trust, {requestID, decision, authenticatorSignature}).
-record(authenticator2trustLogin, {userName, password, authCertificate}).
-record(target2trustRegister, {name, certificate, targetSignature}).