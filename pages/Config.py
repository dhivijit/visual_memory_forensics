import os
from pathlib import Path

import streamlit as st

import config_store

st.set_page_config(page_title="Config - LLM settings")

st.title("Configuration — LLM & API Keys")
st.markdown("Choose the default model/provider to use for LLM calls and set API keys here.")

# Load persisted values (non-secret) and secrets
persisted_model = config_store.get_nonsecret('llm_model', os.environ.get('LLM_MODEL', 'Perplexity'))
persisted_perplexity = config_store.get_secret('perplexity_key') or os.environ.get("PPLX_API_KEY") or os.environ.get("PERPLEXITY_API_KEY")
persisted_openai = config_store.get_secret('openai_key') or os.environ.get('OPENAI_API_KEY')

if 'llm_model' not in st.session_state:
    st.session_state['llm_model'] = persisted_model
if 'perplexity_key' not in st.session_state:
    st.session_state['perplexity_key'] = persisted_perplexity or ""
if 'openai_key' not in st.session_state:
    st.session_state['openai_key'] = persisted_openai or ""

# Provide a reload button so users can refresh the UI from persisted store (file or keyring)
if st.button("Reload saved config"):
    # re-read persisted values and update session state, then rerun so UI refreshes
    persisted_model = config_store.get_nonsecret('llm_model', os.environ.get('LLM_MODEL', 'Perplexity'))
    persisted_perplexity = config_store.get_secret('perplexity_key') or os.environ.get("PPLX_API_KEY") or os.environ.get("PERPLEXITY_API_KEY")
    persisted_openai = config_store.get_secret('openai_key') or os.environ.get('OPENAI_API_KEY')
    st.session_state['llm_model'] = persisted_model
    st.session_state['perplexity_key'] = persisted_perplexity or ""
    st.session_state['openai_key'] = persisted_openai or ""
    st.experimental_rerun()

col1, col2 = st.columns([2, 3])
with col1:
    model = st.selectbox("Default LLM Provider", options=["Perplexity", "OpenAI"], index=["Perplexity", "OpenAI"].index(st.session_state.get('llm_model', 'Perplexity')))
    st.session_state['llm_model'] = model

with col2:
    st.markdown("API key entries are stored securely when possible (OS keyring). If keyring is not available, keys are saved to a user-only file `~/.vmf_config.json` with restricted permissions.")
    if model == 'Perplexity':
        st.session_state['perplexity_key'] = st.text_input("Perplexity API Key (pplx)", value=st.session_state.get('perplexity_key', ''), type="password")
    elif model == 'OpenAI':
        st.session_state['openai_key'] = st.text_input("OpenAI API Key (sk-...)", value=st.session_state.get('openai_key', ''), type="password")

save_to_disk = st.checkbox("Also save secrets to disk (insecure)", value=False)

if st.button("Save config"):
    # persist non-secret
    config_store.set_nonsecret('llm_model', st.session_state.get('llm_model'))
    # persist secrets
    if st.session_state.get('perplexity_key'):
        if save_to_disk:
            # write to file and remove any keyring entry so the file value is used
            config_store.set_secret_force_file('perplexity_key', st.session_state.get('perplexity_key'))
            try:
                config_store.delete_secret('perplexity_key')
            except Exception:
                pass
        else:
            config_store.set_secret('perplexity_key', st.session_state.get('perplexity_key'))
    else:
        config_store.delete_secret('perplexity_key')
    if st.session_state.get('openai_key'):
        if save_to_disk:
            # write to file and remove any keyring entry so the file value is used
            config_store.set_secret_force_file('openai_key', st.session_state.get('openai_key'))
            try:
                config_store.delete_secret('openai_key')
            except Exception:
                pass
        else:
            config_store.set_secret('openai_key', st.session_state.get('openai_key'))
    else:
        config_store.delete_secret('openai_key')

    st.success("Configuration saved to keyring/file.")
    st.write({
        'llm_model': st.session_state.get('llm_model'),
        'perplexity_key_set': bool(config_store.get_secret('perplexity_key')),
        'openai_key_set': bool(config_store.get_secret('openai_key')),
    })
