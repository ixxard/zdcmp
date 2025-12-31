#!/usr/bin/env swipl
# 
:- use_module(library(clpfd)).
:- dynamic insn/5, func/1, slot/2, stmt/1, ptr_var/2.
:- discontiguous value_at/3.
:- initialization(main).

/* if u wanna learn to read prolog on your own, try reading from bottom to top
   halt and catch hehehe, but not always. , is and and | is or */
main :-
    catch(run, E, (
        format(user_error, "Error: ~w~n", [E]),
        writeln("/* decompiler error */")
    )),
    halt(0).

run :-
    reset_db,
    read_string(user_input, _, S),
    split_string(S, "\n", "", Lines),
    parse_lines(0, Lines),
    recover_slots,
    extract_statements,
    emit_program,
    !.

reset_db :-
    retractall(insn(_,_,_,_,_)),
    retractall(func(_)),
    retractall(slot(_,_)),
    retractall(stmt(_)),
    retractall(ptr_var(_,_)).

parse_hex_or_dec(S, N) :-
    ( sub_string(S, 0, 2, _, "0x") ->
        sub_string(S, 2, _, 0, HexPart),
        atom_string(HexAtom, HexPart),
        atom_number(HexAtom, N, 16)
    ;
        number_string(N, S)
    ).

atom_number(Atom, Number, Base) :-
    atom_codes(Atom, Codes),
    hex_codes_to_number(Codes, Base, 0, Number).

hex_codes_to_number([], _, Acc, Acc).
hex_codes_to_number([C|Cs], Base, Acc, N) :-
    hex_digit_value(C, V),
    Acc1 is Acc * Base + V,
    hex_codes_to_number(Cs, Base, Acc1, N).

% i stole this from when i was trying cryptopals
hex_digit_value(C, V) :- C >= 0'0, C =< 0'9, !, V is C - 0'0.
hex_digit_value(C, V) :- C >= 0'a, C =< 0'f, !, V is C - 0'a + 10.
hex_digit_value(C, V) :- C >= 0'A, C =< 0'F, !, V is C - 0'A + 10.

:- dynamic func_at_addr/2.

parse_lines(_, []).
parse_lines(PC, [L|Ls]) :-
    split_string(L, " \t,:[]#", " \t,:[]#", T),
    ( parse_insn(PC, T) -> PC1 is PC + 1 ; PC1 = PC ),
    parse_lines(PC1, Ls).

% just basically get the symbol name from objdump output
parse_insn(_, [Addr,Raw|_]) :-
    atom_string(RawAtom, Raw),
    sub_atom(RawAtom, 0, 1, _, '<'),
    sub_atom(RawAtom, 1, _, 1, Name),
    assertz(func(Name)),
    ( atom_number(Addr, AddrNum) ->
        assertz(func_at_addr(AddrNum, Name))
    ; true ),
    !.

% arithmetic instrctions
parse_insn(PC, [_PCStr,_Hex,OpStr,D,A,B|_]) :-
    atom_string(Op, OpStr),
    member(Op, [add,sub,mul,sdiv,udiv,madd,msub,fadd,fsub,fmul,fdiv,subs,adds]),
    ( Op = subs -> NormOp = sub
    ; Op = adds -> NormOp = add
    ; NormOp = Op ),
    assertz(insn(PC, NormOp, D, A, B)),
    !.

% logical instructions (INCLUDING EOR)
parse_insn(PC, [_PCStr,_Hex,OpStr,D,A,B|_]) :-
    atom_string(Op, OpStr),
    member(Op, [and,orr,eor,bic]),
    assertz(insn(PC, Op, D, A, B)),
    !.

% shift
parse_insn(PC, [_PCStr,_Hex,OpStr,D,A,B|_]) :-
    atom_string(Op, OpStr),
    member(Op, [lsl,lsr,asr,ror]),
    assertz(insn(PC, Op, D, A, B)),
    !.

% mov
parse_insn(PC, [_PCStr,_Hex,OpStr,D,S|_]) :-
    atom_string(Op, OpStr),
    member(Op, [mov,movz,movk,movn]),
    assertz(insn(PC, mov, D, S, none)),
    !.

% ldr (ptr dereference)
parse_insn(PC, [_PCStr,_Hex,OpStr,D,Ptr|_]) :-
    atom_string(Op, OpStr),
    member(Op, [ldr,ldrb,ldrh,ldp]),
    assertz(insn(PC, load, D, ptr(Ptr), none)),
    !.

% ldr (stack-relative)
parse_insn(PC, [_PCStr,_Hex,OpStr,D,SpStr,O|_]) :-
    atom_string(Op, OpStr),
    member(Op, [ldr,ldrb,ldrh,ldp]),
    atom_string(sp, SpStr),
    parse_hex_or_dec(O, Off),
    assertz(insn(PC, load, D, sp(Off), none)),
    !.

% str (ptr dereference)
parse_insn(PC, [_PCStr,_Hex,OpStr,S,Ptr|_]) :-
    atom_string(Op, OpStr),
    member(Op, [str,strb,strh,stp]),
    assertz(insn(PC, store, ptr(Ptr), S, none)),
    !.

% str (stack-relative) - TRACK AS LOCAL VARIABLES
parse_insn(PC, [_PCStr,_Hex,OpStr,S,SpStr,O|_]) :-
    atom_string(Op, OpStr),
    member(Op, [str,strb,strh,stp]),
    atom_string(sp, SpStr),
    parse_hex_or_dec(O, Off),
    assertz(insn(PC, store, sp(Off), S, none)),
    !.

% cmp
parse_insn(PC, [_PCStr,_Hex,OpStr,A,B|_]) :-
    atom_string(Op, OpStr),
    member(Op, [cmp,cmn,tst]),
    assertz(insn(PC, cmp, A, B, none)),
    !.

% cbz
parse_insn(PC, [_PCStr,_Hex,CbStr,Reg,Target|_]) :-
    member(CbStr, ["cbz","cbnz"]),
    atom_string(Cb, CbStr),
    parse_hex_or_dec(Target, To),
    assertz(insn(PC, branch, Cb, To, Reg)),
    !.

% branch
parse_insn(PC, [_PCStr,_Hex,BrStr,T|_]) :-
    member(BrStr, ["b","b.eq","b.ne","b.lt","b.le","b.gt","b.ge","bl","blr","br"]),
    atom_string(Br, BrStr),
    parse_hex_or_dec(T, To),
    assertz(insn(PC, branch, Br, To, none)),
    !.

% ret
parse_insn(PC, [_PCStr,_Hex,RetStr|_]) :-
    atom_string(ret, RetStr),
    assertz(insn(PC, ret, "w0", none, none)),
    !.

parse_insn(_, _).

arg_reg("w0", arg0).
arg_reg("w1", arg1).
arg_reg("w2", arg2).
arg_reg("w3", arg3).
arg_reg("x0", arg0).
arg_reg("x1", arg1).
arg_reg("x2", arg2).
arg_reg("x3", arg3).
arg_reg("s0", arg0).
arg_reg("s1", arg1).
arg_reg("s2", arg2).
arg_reg("s3", arg3).
arg_reg("d0", arg0).
arg_reg("d1", arg1).
arg_reg("d2", arg2).
arg_reg("d3", arg3).

ptr_to_arg("x0", a).
ptr_to_arg("x1", b).
ptr_to_arg("w0", a).
ptr_to_arg("w1", b).

recover_slots :-
    forall(insn(_, store, sp(O), _, _), ensure_slot(O)),
    forall(insn(_, load, _, sp(O), _), ensure_slot(O)).

ensure_slot(O) :- slot(O, _), !.
ensure_slot(O) :-
    gensym(local_, V),
    assertz(slot(O, V)).

value_at(R, PC, V) :-
    arg_reg(R, V),
    \+ written_before(R, PC),
    !.

written_before(R, PC) :-
    insn(P, _, R, _, _),
    P < PC,
    !.

value_at(R, PC, V) :-
    insn(MovPC, mov, R, Source, _),
    MovPC < PC,
    \+ written_after_mov(R, MovPC, PC),
    catch(value_at(Source, MovPC, V), _, fail),
    !.

written_after_mov(R, MovPC, PC) :-
    insn(P, Op, R, _, _),
    Op \= mov,
    P > MovPC,
    P < PC,
    !.

value_at(R, PC, Expr) :-
    findall(P-Op-A-B, (
        insn(P, Op, R, A, B),
        P < PC
    ), Writes),
    Writes \= [],
    last(Writes, LastP-LastOp-LastA-LastB),
    !,
    ( is_binary_op(LastOp) ->
        catch(value_at(LastA, LastP, VA), _, VA = LastA),
        catch(value_at(LastB, LastP, VB), _, VB = LastB),
        ( VA = sp(O1) -> catch(value_at(sp(O1), LastP, VA2), _, VA2 = VA) ; VA2 = VA ),
        ( VB = sp(O2) -> catch(value_at(sp(O2), LastP, VB2), _, VB2 = VB) ; VB2 = VB ),
        Expr =.. [LastOp, VA2, VB2]
    ; LastOp = load ->
        ( LastA = sp(_) ->
            catch(value_at(LastA, LastP, Expr), _, Expr = LastA)
        ; LastA = ptr(PtrReg) ->
            catch(value_at(PtrReg, LastP, PtrVal), _, PtrVal = PtrReg),
            Expr = deref(PtrVal)
        ;
            catch(value_at(LastA, LastP, Expr), _, Expr = LastA)
        )
    ; LastOp = mov ->
        catch(value_at(LastA, LastP, Expr), _, Expr = LastA)
    ; LastOp = call ->
        resolve_call_expr(LastA, LastP, Expr)
    ;
        Expr = R
    ).

value_at(sp(O), PC, V) :-
    findall(P-S, (
        insn(P, store, sp(O), S, _),
        P < PC,
        \+ overwritten(sp(O), P, PC)
    ), Stores),
    Stores \= [],
    last(Stores, LastP-LastS),
    !,
    catch(value_at(LastS, LastP, V), _, V = LastS),
    ( member(V, [arg0, arg1, arg2, arg3]) -> true ; true ).

value_at(ptr(PtrReg), PC, V) :-
    findall(P-S, (
        insn(P, store, ptr(PtrReg), S, _),
        P < PC,
        \+ overwritten_ptr(ptr(PtrReg), P, PC)
    ), Stores),
    Stores \= [],
    last(Stores, LastP-LastS),
    !,
    catch(value_at(LastS, LastP, V), _, V = LastS).

overwritten(L, From, To) :-
    insn(P, store, L, _, _),
    P > From,
    P < To,
    !.

overwritten_ptr(ptr(Reg), From, To) :-
    insn(P, store, ptr(Reg), _, _),
    P > From,
    P < To,
    !.

value_at(R, _PC, R) :- !.

resolve_call_expr(Target, PC, call(FuncName, Args)) :-
    ( atom_number(Target, Addr) ->
        resolve_func_name(Addr, FuncName)
    ;
        FuncName = Target
    ),
    collect_call_args(PC, Args).

resolve_func_name(Addr, Name) :-
    func_at_addr(Addr, Name), !.
resolve_func_name(Addr, Name) :-
    atom_concat('func_', Addr, Name).

collect_call_args(PC, Args) :-
    findall(Arg, (
        member(Reg, ["w0", "w1", "w2", "w3"]),
        catch(value_at(Reg, PC, Val), _, Val = Reg),
        Val \= Reg,
        Arg = Val
    ), Args).

is_binary_op(add).
is_binary_op(sub).
is_binary_op(mul).
is_binary_op(sdiv).
is_binary_op(udiv).
is_binary_op(fadd).
is_binary_op(fsub).
is_binary_op(fmul).
is_binary_op(fdiv).
is_binary_op(and).
is_binary_op(orr).
is_binary_op(eor).
is_binary_op(lsl).
is_binary_op(lsr).
is_binary_op(asr).

extract_statements :-
    extract_pointer_ops,
    extract_assigns,
    extract_return,
    extract_control_flow.

extract_pointer_ops :-
    forall(
        insn(PC, store, ptr(PtrReg), S, _),
        (
            catch(value_at(S, PC, E), _, E = S),
            ( ptr_to_arg(PtrReg, PtrArg) ->
                assertz(stmt(ptr_assign(PtrArg, E)))
            ;
                assertz(stmt(ptr_assign(PtrReg, E)))
            )
        )
    ).

extract_assigns :-
    forall(
        (insn(PC, store, sp(O), S, _), slot(O, V)),
        (
            catch(value_at(S, PC, E), _, E = S),
            ( \+ is_simple_param_store(E) ->
                assertz(stmt(assign(V, E)))
            ;
                true
            )
        )
    ).

is_simple_param_store(E) :-
    member(E, [arg0, arg1, arg2, arg3]).

extract_return :-
    insn(PC, ret, _, _, _),
    !,
    catch(value_at("w0", PC, E), _, E = "w0"),
    assertz(stmt(return(E))).
extract_return.

extract_control_flow :-
    forall(
        insn(PC, branch, Br, Target, Reg),
        extract_branch(PC, Br, Target, Reg)
    ).

extract_branch(PC, b, Target, _) :-
    ( Target < PC ->
        true
    ;
        true
    ),
    !.

extract_branch(PC, cbz, Target, Reg) :-
    ( Target > PC ->
        catch(value_at(Reg, PC, Val), _, Val = Reg),
        CondExpr =.. ['==', Val, 0],
        assertz(stmt(if(CondExpr, [])))
    ; Target < PC ->
        catch(value_at(Reg, PC, Val), _, Val = Reg),
        CondExpr =.. ['!=', Val, 0],
        assertz(stmt(while(CondExpr, [])))
    ; true ),
    !.

extract_branch(PC, cbnz, Target, Reg) :-
    ( Target > PC ->
        catch(value_at(Reg, PC, Val), _, Val = Reg),
        CondExpr =.. ['!=', Val, 0],
        assertz(stmt(if(CondExpr, [])))
    ; Target < PC ->
        catch(value_at(Reg, PC, Val), _, Val = Reg),
        CondExpr =.. ['!=', Val, 0],
        assertz(stmt(while(CondExpr, [])))
    ; true ),
    !.

extract_branch(PC, Br, Target, _) :-
    Br \= b,
    ( Target < PC ->
        extract_loop_with_body(PC, Br, Target)
    ; Target > PC ->
        extract_if(PC, Br, Target)
    ;
        true
    ).

extract_loop_with_body(PC, Br, LoopStart) :-
    PC1 is PC - 1,
    ( insn(PC1, cmp, A, B, _) ->
        catch(value_at(A, PC1, VA), _, VA = A),
        catch(value_at(B, PC1, VB), _, VB = B),
        branch_to_condition(Br, Cond),
        CondExpr =.. [Cond, VA, VB],
        % Collect statements in loop body (from LoopStart to PC1)
        findall(S, (
            stmt(S),
            get_stmt_pc(S, StmtPC),
            StmtPC >= LoopStart,
            StmtPC < PC1
        ), BodyStmts),
        assertz(stmt(while(CondExpr, BodyStmts)))
    ;
        true
    ).

get_stmt_pc(assign(V, _), PC) :-
    slot(O, V),
    insn(PC, store, sp(O), _, _), !.
get_stmt_pc(ptr_assign(_, _), PC) :-
    insn(PC, store, ptr(_), _, _), !.
get_stmt_pc(_, 0).

extract_if(PC, Br, _Target) :-
    PC1 is PC - 1,
    ( insn(PC1, cmp, A, B, _) ->
        catch(value_at(A, PC1, VA), _, VA = A),
        catch(value_at(B, PC1, VB), _, VB = B),
        branch_to_condition(Br, Cond),
        invert_condition(Cond, InvCond),
        CondExpr =.. [InvCond, VA, VB],
        assertz(stmt(if(CondExpr, [])))
    ;
        true
    ).

branch_to_condition('b.eq', '==').
branch_to_condition('b.ne', '!=').
branch_to_condition('b.lt', '<').
branch_to_condition('b.le', '<=').
branch_to_condition('b.gt', '>').
branch_to_condition('b.ge', '>=').

invert_condition('==', '!=').
invert_condition('!=', '==').
invert_condition('<', '>=').
invert_condition('<=', '>').
invert_condition('>', '<=').
invert_condition('>=', '<').

emit_program :-
    ( func(F) -> true ; F = xor_swap ),
    collect_params(Params),
    detect_return_type(RetType),
    format("~w ~w(", [RetType, F]),
    emit_params(Params),
    writeln(") {"),
    emit_body,
    writeln("}").

% very childlike type detector? IDK how to do it in real programs
detect_return_type(RetType) :-
    insn(RetPC, ret, _, _, _),
    ( written_before("d0", RetPC) -> RetType = 'double'
    ; written_before("s0", RetPC) -> RetType = 'float'
    ; written_before("w0", RetPC) -> RetType = 'int'
    ; written_before("x0", RetPC) -> RetType = 'long'
    ; RetType = 'void' ).

collect_params(Params) :-
    findall(ArgName, (
        ( stmt(assign(_, E)) ; stmt(ptr_assign(_, E)) ; stmt(return(E)) ),
        sub_term(ArgName, E),
        member(ArgName, [arg0, arg1, arg2, arg3])
    ), UsedArgs1),
    findall(ArgName, (
        ( stmt(if(C, _)) ; stmt(while(C, _)) ),
        sub_term(ArgName, C),
        member(ArgName, [arg0, arg1, arg2, arg3])
    ), UsedArgs2),
    append(UsedArgs1, UsedArgs2, UsedArgs0),
    sort(UsedArgs0, UsedArgs),
    
    findall(ArgName, (
        member(ArgName, UsedArgs),
        arg_reg(Reg, ArgName),
        used_as_pointer(Reg)
    ), PtrArgs0),
    sort(PtrArgs0, PtrArgs),
    
    subtract(UsedArgs, PtrArgs, ValArgs),
    
    findall(P, (
        member(ArgName, PtrArgs),
        atom_concat('int *', ArgName, P)
    ), PtrParams),
    
    findall(P, (
        member(ArgName, ValArgs),
        detect_param_type(ArgName, Type),
        atom_concat(Type, ' ', TypeSpace),
        atom_concat(TypeSpace, ArgName, P)
    ), ValParams),
    
    append(PtrParams, ValParams, AllParams),
    ( AllParams = [] -> Params = ['void'] ; Params = AllParams ).

detect_param_type(ArgName, Type) :-
    ( arg_reg(Reg, ArgName), atom_string(Reg, RegStr), sub_string(RegStr, 0, 1, _, "d"), 
      insn(_, _, Reg, _, _) -> Type = 'double'
    ; arg_reg(Reg, ArgName), atom_string(Reg, RegStr), sub_string(RegStr, 0, 1, _, "s"),
      insn(_, _, Reg, _, _) -> Type = 'float'
    ; arg_reg(Reg, ArgName), atom_string(Reg, RegStr), sub_string(RegStr, 0, 1, _, "x"),
      insn(_, _, Reg, _, _) -> Type = 'long'
    ; Type = 'int' ).

used_as_pointer(Reg) :-
    ( insn(_, load, _, ptr(Reg), _) ; insn(_, store, ptr(Reg), _, _) ), !.

emit_params([]) :- !.
emit_params([P]) :-
    format("~w", [P]), !.
emit_params([P|Ps]) :-
    format("~w, ", [P]),
    emit_params(Ps).

emit_body :-
    findall(S, stmt(S), Ss),
    ( Ss = [] ->
        writeln("  /* unable to reconstruct body */")
    ;
        forall(member(S, Ss), emit_stmt(S))
    ).

emit_stmt(assign(V, E)) :-
    format("  ~w = ", [V]),
    emit_expr(E),
    writeln(";").

emit_stmt(ptr_assign(V, E)) :-
    format("  *~w = ", [V]),
    emit_expr(E),
    writeln(";").

emit_stmt(return(E)) :-
    write("  return "),
    emit_expr(E),
    writeln(";").

emit_stmt(if(C, _B)) :-
    write("  if ("),
    emit_expr(C),
    writeln(") { }").

emit_stmt(while(C, Body)) :-
    write("  while ("),
    emit_expr(C),
    writeln(") {"),
    ( Body = [] ->
        true
    ;
        forall(member(S, Body), (write("    "), emit_stmt_inner(S)))
    ),
    writeln("  }").

emit_stmt_inner(assign(V, E)) :-
    format("~w = ", [V]), emit_expr(E), writeln(";").
emit_stmt_inner(ptr_assign(V, E)) :-
    format("*~w = ", [V]), emit_expr(E), writeln(";").
emit_stmt_inner(return(E)) :-
    write("return "), emit_expr(E), writeln(";").

emit_expr(E) :- atomic(E), !, write(E).
emit_expr(sp(O)) :-
    !,
    (slot(O, V) -> write(V) ; format("sp[~w]", [O])).

emit_expr(deref(Ptr)) :-
    !,
    write("*"),
    emit_expr(Ptr).

emit_expr(call(FuncName, Args)) :-
    !,
    write(FuncName),
    write("("),
    emit_arg_list(Args),
    write(")").

emit_expr(E) :-
    E =.. [Op, A, B],
    c_operator(Op, COp),
    write("("),
    emit_expr(A),
    format(" ~w ", [COp]),
    emit_expr(B),
    write(")").

emit_arg_list([]).
emit_arg_list([A]) :-
    emit_expr(A), !.
emit_arg_list([A|As]) :-
    emit_expr(A),
    write(", "),
    emit_arg_list(As).

c_operator(add, '+').
c_operator(sub, '-').
c_operator(mul, '*').
c_operator(sdiv, '/').
c_operator(udiv, '/').
c_operator(fadd, '+').
c_operator(fsub, '-').
c_operator(fmul, '*').
c_operator(fdiv, '/').
c_operator(and, '&').
c_operator(orr, '|').
c_operator(eor, '^').
c_operator(lsl, '<<').
c_operator(lsr, '>>').
c_operator(asr, '>>').
c_operator('==', '==').
c_operator('!=', '!=').
c_operator('<', '<').
c_operator('<=', '<=').
c_operator('>', '>').
c_operator('>=', '>=').
c_operator(Op, Op).
