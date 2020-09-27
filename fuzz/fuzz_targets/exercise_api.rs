#![no_main]
use arbitrary::{self, Arbitrary, Unstructured};
use libfuzzer_sys::fuzz_target;
use std::collections::HashMap;
use urkel::{Database, Key};

#[derive(Arbitrary, Clone, Debug)]
enum Action {
    Flush,
    NewTx(TxId),
    NewTxAt(TxId, StateId),
    TxAssertGet(TxId, Key, Value),
    TxAssertShouldHave(TxId, Key),
    TxSet(TxId, Key, Value),
    TxRemove(TxId, Key, bool),
    TxRevert(TxId, StateId),
    TxDrop(TxId),
    TxCommit(TxId, StateId),
}

/// The state id is a simplification of state root.
#[derive(Copy, Clone, Debug, Arbitrary, Hash, Eq, PartialEq)]
struct StateId(usize);

#[derive(Copy, Clone, Debug, Arbitrary, Hash, Eq, PartialEq)]
struct TxId(usize);

/// A byte buffer that is limited to the maximum value size.
#[derive(Clone, Debug, Arbitrary)]
struct Value(Vec<u8>);

struct Scope {
    id: usize,
    active_txs: Vec<TxId>,
    txs: HashMap<TxId, HashMap<Key, Value>>,
    states: Vec<StateId>,
    state_kvs: HashMap<StateId, HashMap<Key, Value>>,
}

impl Scope {
    fn new() -> Self {
        let zero_state = StateId(0);

        let mut state_kvs = HashMap::new();
        state_kvs.insert(zero_state, HashMap::new());

        Self {
            id: 1,
            active_txs: Vec::new(),
            txs: HashMap::new(),
            states: vec![zero_state],
            state_kvs,
        }
    }

    fn new_tx(&mut self) -> TxId {
        let id = TxId(self.id);
        self.id += 1;
        self.active_txs.push(id);
        self.txs.insert(id, HashMap::new());
        id
    }

    fn new_state(&mut self) -> StateId {
        let id = StateId(self.id);
        self.id += 1;
        self.states.push(id);
        id
    }
}

#[derive(Debug)]
pub struct Actions {
    actions: Vec<Action>,
}

impl Arbitrary for Actions {
    fn arbitrary(input: &mut Unstructured) -> arbitrary::Result<Self> {
        // TODO: swarm

        let mut actions = vec![];

        let mut scope = Scope::new();

        for _ in 0..input.arbitrary_len::<Action>()? {
            let mut choices: Vec<fn(&mut Unstructured, &mut Scope) -> arbitrary::Result<Action>> =
                vec![];

            choices.push(|_, scope| {
                let id = scope.new_tx();
                Ok(Action::NewTx(id))
            });

            choices.push(|input, scope| {
                let id = scope.new_tx();
                let state = *input.choose(&scope.states)?;
                Ok(Action::NewTxAt(id, state))
            });

            if !scope.active_txs.is_empty() {
                choices.push(|input, scope| {
                    let tx = *input.choose(&scope.active_txs)?;
                    let key = Key::arbitrary(input)?;
                    let value = Value::arbitrary(input)?;
                    scope
                        .txs
                        .get_mut(&tx)
                        .unwrap()
                        .insert(key.clone(), value.clone());
                    Ok(Action::TxSet(tx, key, value))
                });

                fn non_empty_txs<'a>(scope: &'a Scope) -> impl Iterator<Item = TxId> + 'a {
                    scope.txs.iter().filter_map(move |(tx_id, map)| {
                        if !map.is_empty() && scope.active_txs.contains(&tx_id) {
                            Some(*tx_id)
                        } else {
                            None
                        }
                    })
                }
                if non_empty_txs(&scope).any(|_| true) {
                    choices.push(|input, scope| {
                        let tx = *input.choose(&non_empty_txs(scope).collect::<Vec<_>>())?;
                        let kvs = scope.txs[&tx].iter().collect::<Vec<_>>();
                        let (k, v) = *input.choose(&kvs)?;
                        Ok(Action::TxAssertGet(tx, *k, v.clone()))
                    });

                    choices.push(|input, scope| {
                        let tx = *input.choose(&non_empty_txs(scope).collect::<Vec<_>>())?;
                        let keys = scope.txs[&tx].keys().collect::<Vec<_>>();
                        let key = *input.choose(&keys)?;
                        Ok(Action::TxAssertShouldHave(tx, *key))
                    });

                    choices.push(|input, scope| {
                        let tx = *input.choose(&non_empty_txs(scope).collect::<Vec<_>>())?;
                        let keys = scope.txs[&tx].keys().collect::<Vec<_>>();
                        let key = **input.choose(&keys)?;
                        let _ = scope.txs.get_mut(&tx).unwrap().remove(&key);
                        Ok(Action::TxRemove(tx, key, true))
                    });
                }

                // random remove
                choices.push(|input, scope| {
                    let tx = *input.choose(&scope.active_txs)?;
                    let key = Key::arbitrary(input)?;
                    let _ = scope.txs.get_mut(&tx).unwrap().remove(&key);
                    Ok(Action::TxRemove(tx, key, false))
                });

                choices.push(|input, scope| {
                    let tx = *input.choose(&scope.active_txs)?;
                    let state_id = scope.new_state();
                    let state_kv = scope.txs[&tx].clone();
                    scope.state_kvs.insert(state_id, state_kv);
                    Ok(Action::TxCommit(tx, state_id))
                });

                choices.push(|input, scope| {
                    let tx = *input.choose(&scope.active_txs)?;
                    scope.active_txs.retain(|x| *x != tx);
                    Ok(Action::TxDrop(tx))
                });

                choices.push(|input, scope| {
                    let tx = *input.choose(&scope.active_txs)?;
                    let state_id = *input.choose(&scope.states)?;
                    let state_kv = scope.state_kvs[&state_id].clone();
                    *scope.txs.get_mut(&tx).unwrap() = state_kv;
                    Ok(Action::TxRevert(tx, state_id))
                });
            }

            choices.push(|_, scope| {
                scope.active_txs.clear();
                Ok(Action::Flush)
            });

            if choices.is_empty() {
                break;
            }
            let c = input.choose(&choices)?;
            actions.push(c(input, &mut scope)?);
        }

        Ok(Actions { actions })
    }
}

fuzz_target!(|actions: Actions| {
    let prefix_dir = tempfile::tempdir().unwrap();

    let mut states_to_roots = HashMap::new();
    states_to_roots.insert(StateId(0), [0; 32]);

    let mut actions = actions.actions.into_iter();

    loop {
        let db = Database::open(prefix_dir.path().display().to_string()).unwrap();
        let mut txs = HashMap::new();

        while let Some(action) = actions.next() {
            match action {
                Action::NewTx(tx_id) => {
                    txs.insert(tx_id, db.new_tx().unwrap());
                }
                Action::NewTxAt(tx_id, state) => {
                    let root = states_to_roots[&state];
                    txs.insert(tx_id, db.new_tx_at(root).unwrap());
                }
                Action::TxSet(tx, k, v) => {
                    txs.get_mut(&tx).unwrap().insert(&k, &v.0).unwrap();
                }
                Action::TxAssertGet(tx, k, expected_value) => {
                    let actual_value = txs.get_mut(&tx).unwrap().get(&k).unwrap();
                    assert_eq!(Some(expected_value.0), actual_value);
                }
                Action::TxAssertShouldHave(tx, k) => {
                    assert!(txs.get_mut(&tx).unwrap().has(&k).unwrap());
                }
                Action::TxRemove(tx, k, must_exist) => {
                    let r = txs.get_mut(&tx).unwrap().remove(&k);
                    if must_exist {
                        assert!(r.is_ok());
                    }
                }
                Action::TxDrop(tx_id) => {
                    let _ = txs.remove(&tx_id).unwrap();
                }
                Action::TxCommit(tx_id, state) => {
                    let tx = txs.get_mut(&tx_id).unwrap();
                    tx.commit().unwrap();
                    states_to_roots.insert(state, tx.root());
                }
                Action::TxRevert(tx_id, state) => {
                    let root = states_to_roots[&state];
                    txs.get_mut(&tx_id).unwrap().revert(root).unwrap();
                }
                Action::Flush => {
                    continue;
                }
            }
        }

        break;
    }
});
