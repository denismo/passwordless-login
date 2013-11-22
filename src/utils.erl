%%%-------------------------------------------------------------------
%%% @author Denis Mikhalkin
%%% @copyright (C) 2013, Denis Mikhalkin
%%% @doc
%%%
%%% @end
%%% Created : 16. Nov 2013 10:53 PM
%%%-------------------------------------------------------------------
-module(utils).
-vsn(1.0).

%% API
-export([signedRecord2list/1]).

signedRecord2list(Record) ->
  lists:reverse(append_elements(tuple_size(Record), Record)).

append_elements(0,_Record) ->
  [];
append_elements(Index,Record) ->
  [element(Index, Record) | append_elements(Index-1, Record)].
