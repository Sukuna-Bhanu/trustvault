/**
 * TrustVault - Client-Side Security Dashboard Controller
 * Pure Vanilla JavaScript ES2022
 */

(function () {
    'use strict';

    // Application State
    const state = {
        token: localStorage.getItem('tv_token') || null,
        user: JSON.parse(localStorage.getItem('tv_user') || 'null'),
        usersList: [],
        documentsList: [],
        activeDocumentId: null,
    };

    // DOM Elements
    const elements = {
        // Nav
        navRoleBadge: document.getElementById('nav-role-badge'),
        navUserEmail: document.getElementById('nav-user-email'),
        btnLogout: document.getElementById('btn-logout'),
        systemStatusText: document.getElementById('system-status-text'),

        // Persona Switcher
        btnSwitchAdmin: document.getElementById('btn-switch-admin'),
        btnSwitchOwner: document.getElementById('btn-switch-owner'),
        btnSwitchViewer: document.getElementById('btn-switch-viewer'),
        sessionUserId: document.getElementById('session-user-id'),
        sessionTokenPreview: document.getElementById('session-token-preview'),
        btnCopyToken: document.getElementById('btn-copy-token'),
        btnCopyUserId: document.getElementById('btn-copy-user-id'),
        formManualLogin: document.getElementById('form-manual-login'),
        inputLoginEmail: document.getElementById('input-login-email'),
        inputLoginPassword: document.getElementById('input-login-password'),

        // Document Vault
        formUpload: document.getElementById('form-upload-document'),
        dropZone: document.getElementById('drop-zone'),
        inputFile: document.getElementById('input-file'),
        dropZoneTitle: document.getElementById('drop-zone-title'),
        selectedFileName: document.getElementById('selected-file-name'),
        selectCategory: document.getElementById('select-category'),
        uploadFeedback: document.getElementById('upload-feedback'),
        btnTestRealPdf: document.getElementById('btn-test-real-pdf'),
        btnTestFakePdf: document.getElementById('btn-test-fake-pdf'),
        btnRefreshDocs: document.getElementById('btn-refresh-docs'),
        documentsTbody: document.getElementById('documents-tbody'),

        // Permissions
        inputTargetDocId: document.getElementById('input-target-doc-id'),
        inputTargetUserId: document.getElementById('input-target-user-id'),
        selectPermissionType: document.getElementById('select-permission-type'),
        btnSelectLatestDoc: document.getElementById('btn-select-latest-doc'),
        btnSelectViewerId: document.getElementById('btn-select-viewer-id'),
        btnGrantPerm: document.getElementById('btn-grant-perm'),
        btnRevokePerm: document.getElementById('btn-revoke-perm'),
        permissionFeedback: document.getElementById('permission-feedback'),
        btnRefreshGrants: document.getElementById('btn-refresh-grants'),
        grantsList: document.getElementById('grants-list'),
        grantsPlaceholder: document.getElementById('grants-placeholder'),

        // Ledger
        btnVerifyLedger: document.getElementById('btn-verify-ledger'),
        ledgerStatusBanner: document.getElementById('ledger-status-banner'),
        ledgerBadgeChip: document.getElementById('ledger-badge-chip'),
        ledgerHeadline: document.getElementById('ledger-headline'),
        ledgerTotalBlocks: document.getElementById('ledger-total-blocks'),
        ledgerVerifiedAt: document.getElementById('ledger-verified-at'),
        chainExplorer: document.getElementById('chain-explorer'),

        // Toast Container
        toastContainer: document.getElementById('toast-container'),
    };

    // ==========================================================================
    // Toast Notification System
    // ==========================================================================
    function showToast(message, type = 'info', duration = 4000) {
        const toast = document.createElement('div');
        toast.className = `toast toast-${type}`;
        toast.textContent = message;
        elements.toastContainer.appendChild(toast);

        setTimeout(() => {
            toast.style.opacity = '0';
            toast.style.transform = 'translateY(10px)';
            toast.style.transition = 'all 0.3s ease';
            setTimeout(() => toast.remove(), 300);
        }, duration);
    }

    // ==========================================================================
    // Authentication & Session Management
    // ==========================================================================
    function setSession(token, user) {
        state.token = token;
        state.user = user;
        if (token) {
            localStorage.setItem('tv_token', token);
            localStorage.setItem('tv_user', JSON.stringify(user));
        } else {
            localStorage.removeItem('tv_token');
            localStorage.removeItem('tv_user');
        }
        updateSessionUI();
        refreshAllData();
    }

    function updateSessionUI() {
        if (state.user && state.token) {
            elements.navRoleBadge.textContent = state.user.role;
            elements.navRoleBadge.className = `role-pill role-${state.user.role.toLowerCase()}`;
            elements.navUserEmail.textContent = state.user.email;
            elements.btnLogout.style.display = 'inline-flex';

            elements.sessionUserId.textContent = state.user.id;
            elements.sessionTokenPreview.textContent = `${state.token.slice(0, 20)}...${state.token.slice(-16)}`;

            // Highlight active persona button
            [elements.btnSwitchAdmin, elements.btnSwitchOwner, elements.btnSwitchViewer].forEach(btn => {
                if (btn) {
                    btn.classList.toggle('active', btn.dataset.email === state.user.email);
                }
            });
        } else {
            elements.navRoleBadge.textContent = 'NO SESSION';
            elements.navRoleBadge.className = 'role-pill role-none';
            elements.navUserEmail.textContent = 'Not Authenticated';
            elements.btnLogout.style.display = 'none';

            elements.sessionUserId.textContent = 'None';
            elements.sessionTokenPreview.textContent = 'No active token';

            [elements.btnSwitchAdmin, elements.btnSwitchOwner, elements.btnSwitchViewer].forEach(btn => {
                if (btn) btn.classList.remove('active');
            });
        }
    }

    async function login(email, password) {
        try {
            const res = await fetch('/api/auth/login', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ email, password }),
            });
            const data = await res.json();
            if (!res.ok) {
                showToast(data.error || 'Login failed', 'error');
                return false;
            }
            setSession(data.token, data.user);
            showToast(`Authenticated as ${data.user.role} (${data.user.email})`, 'success');
            return true;
        } catch (err) {
            showToast('Network error during authentication', 'error');
            return false;
        }
    }

    async function fetchUsers() {
        try {
            const res = await fetch('/api/auth/users');
            if (res.ok) {
                const data = await res.json();
                state.usersList = data.users || [];
            }
        } catch (err) {
            console.error('Failed to fetch users:', err);
        }
    }

    // ==========================================================================
    // Document Vault Operations
    // ==========================================================================
    async function loadDocuments() {
        if (!state.token) {
            elements.documentsTbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">Please log in to view documents.</td></tr>';
            return;
        }

        elements.documentsTbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">Loading vault records...</td></tr>';
        try {
            const res = await fetch('/api/documents', {
                headers: { Authorization: `Bearer ${state.token}` },
            });
            if (!res.ok) {
                elements.documentsTbody.innerHTML = `<tr><td colspan="6" class="text-center text-muted">Error loading documents (${res.status})</td></tr>`;
                return;
            }
            const data = await res.json();
            state.documentsList = data.documents || [];
            renderDocumentsTable(state.documentsList);
        } catch (err) {
            elements.documentsTbody.innerHTML = '<tr><td colspan="6" class="text-center text-muted">Network error loading documents.</td></tr>';
        }
    }

    function renderDocumentsTable(docs) {
        if (!docs || docs.length === 0) {
            elements.documentsTbody.innerHTML = `
                <tr>
                    <td colspan="6" class="text-center text-muted" style="padding: 1.5rem;">
                        No authorized documents found in vault for this user.
                        ${state.user?.role === 'VIEWER' ? '<br><small>Zero-Trust Mode: Viewers have no document access until granted by an Owner.</small>' : ''}
                    </td>
                </tr>
            `;
            return;
        }

        elements.documentsTbody.innerHTML = '';
        docs.forEach(doc => {
            const tr = document.createElement('tr');
            const sizeKb = (doc.file_size / 1024).toFixed(1);
            const isOwner = state.user?.id === doc.owner_id || state.user?.role === 'ADMIN';

            tr.innerHTML = `
                <td>
                    <strong>${escapeHtml(doc.original_name)}</strong>
                </td>
                <td>
                    <span class="role-pill ${doc.mime_type === 'application/pdf' ? 'role-admin' : 'role-owner'}">${escapeHtml(doc.mime_type)}</span>
                    <span class="text-xs text-muted" style="margin-left: 4px;">(${escapeHtml(doc.category)})</span>
                </td>
                <td>${sizeKb} KB</td>
                <td>
                    <code class="meta-code" style="cursor: pointer;" title="Click to copy ID" data-copy-id="${doc.id}">
                        ${doc.id.slice(0, 8)}...${doc.id.slice(-6)}
                    </code>
                </td>
                <td>
                    <span class="text-xs ${isOwner ? 'text-emerald' : 'text-muted'}">${escapeHtml(doc.owner_email || 'Unknown')}</span>
                </td>
                <td>
                    <div style="display: flex; gap: 0.35rem;">
                        <button class="btn-xs btn-primary btn-download" data-doc-id="${doc.id}" data-filename="${escapeHtml(doc.original_name)}">
                            <svg viewBox="0 0 24 24" width="12" height="12" fill="none" stroke="currentColor" stroke-width="2"><path d="M21 15v4a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2v-4"/><polyline points="7 10 12 15 17 10"/><line x1="12" y1="15" x2="12" y2="3"/></svg>
                            Download
                        </button>
                        <button class="btn-xs btn-outline btn-select-doc" data-doc-id="${doc.id}" title="Select for Permission Manager">
                            Select
                        </button>
                    </div>
                </td>
            `;
            elements.documentsTbody.appendChild(tr);
        });

        // Attach event listeners for download and select buttons
        elements.documentsTbody.querySelectorAll('.btn-download').forEach(btn => {
            btn.addEventListener('click', () => downloadDocument(btn.dataset.docId, btn.dataset.filename));
        });

        elements.documentsTbody.querySelectorAll('.btn-select-doc').forEach(btn => {
            btn.addEventListener('click', () => {
                selectDocumentForPermission(btn.dataset.docId);
            });
        });

        elements.documentsTbody.querySelectorAll('[data-copy-id]').forEach(code => {
            code.addEventListener('click', () => {
                navigator.clipboard.writeText(code.dataset.copyId);
                showToast(`Copied UUID: ${code.dataset.copyId}`, 'info');
            });
        });
    }

    async function downloadDocument(docId, filename) {
        if (!state.token) {
            showToast('Authentication required to download', 'error');
            return;
        }

        try {
            const res = await fetch(`/api/documents/${docId}/download`, {
                headers: { Authorization: `Bearer ${state.token}` },
            });

            if (res.status === 404) {
                // Anti-enumeration 404 concealment verification
                showToast('404 Not Found: Access Denied / Document Concealed (Standard 1 Anti-Enumeration)', 'error', 5000);
                refreshAuditLedger();
                return;
            }

            if (!res.ok) {
                const errData = await res.json().catch(() => ({}));
                showToast(`Download failed: ${errData.error || res.statusText}`, 'error');
                return;
            }

            const blob = await res.blob();
            const url = window.URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = filename || 'vault_document.bin';
            document.body.appendChild(a);
            a.click();
            a.remove();
            window.URL.revokeObjectURL(url);
            showToast(`Downloaded: ${filename}`, 'success');
            refreshAuditLedger();
        } catch (err) {
            showToast('Download error occurred', 'error');
        }
    }

    async function uploadFile(file, category = 'confidential') {
        if (!state.token) {
            showToast('Authentication required to upload', 'error');
            return;
        }

        const formData = new FormData();
        formData.append('file', file);
        formData.append('category', category);

        // Pre-display banner in pending state
        elements.uploadFeedback.style.display = 'block';
        elements.uploadFeedback.className = 'feedback-banner feedback-success';
        elements.uploadFeedback.textContent = 'Inspecting raw magic-byte header buffer on server...';

        try {
            const res = await fetch('/api/documents/upload', {
                method: 'POST',
                headers: { Authorization: `Bearer ${state.token}` },
                body: formData,
            });

            const data = await res.json();
            if (res.status === 201) {
                elements.uploadFeedback.className = 'feedback-banner feedback-success';
                elements.uploadFeedback.innerHTML = `
                    <strong>✓ Standard 3 Magic-Byte Header Validated!</strong><br>
                    File <code>${escapeHtml(file.name)}</code> confirmed genuine (MIME: ${escapeHtml(data.document.mime_type)}). Stored securely under storage UUID <code>${data.document.storage_key}</code>.
                `;
                showToast('Document uploaded successfully!', 'success');
                // Reset inputs
                elements.inputFile.value = '';
                elements.selectedFileName.style.display = 'none';
                elements.dropZoneTitle.innerHTML = 'Drag & drop document, or <span class="browse-link">browse</span>';
                loadDocuments();
                refreshAuditLedger();
            } else {
                elements.uploadFeedback.className = 'feedback-banner feedback-error';
                elements.uploadFeedback.innerHTML = `
                    <strong>✗ Rejected with HTTP ${res.status}:</strong><br>
                    ${escapeHtml(data.error || 'File validation failed.')}
                `;
                showToast('Upload rejected: Spoofed magic bytes detected', 'error');
                refreshAuditLedger();
            }
        } catch (err) {
            elements.uploadFeedback.className = 'feedback-banner feedback-error';
            elements.uploadFeedback.textContent = 'Upload network request failed.';
        }
    }

    // ==========================================================================
    // Permissions Operations
    // ==========================================================================
    function selectDocumentForPermission(docId) {
        state.activeDocumentId = docId;
        elements.inputTargetDocId.value = docId;
        loadGrantsForDocument(docId);
        elements.inputTargetDocId.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        showToast(`Selected Document ID: ${docId}`, 'info');
    }

    async function loadGrantsForDocument(docId) {
        if (!docId || !state.token) return;
        elements.grantsList.innerHTML = '';
        elements.grantsPlaceholder.style.display = 'block';
        elements.grantsPlaceholder.textContent = 'Fetching real-time grants from database...';

        try {
            const res = await fetch(`/api/permissions/grants/${docId}`, {
                headers: { Authorization: `Bearer ${state.token}` },
            });

            if (!res.ok) {
                elements.grantsPlaceholder.textContent = 'Unable to fetch grants (Must be document owner or admin).';
                return;
            }

            const data = await res.json();
            const grants = data.grants || [];

            if (grants.length === 0) {
                elements.grantsPlaceholder.textContent = 'No active named grants. Access restricted exclusively to owner.';
                return;
            }

            elements.grantsPlaceholder.style.display = 'none';
            grants.forEach(g => {
                const li = document.createElement('li');
                li.className = 'grant-item';
                li.innerHTML = `
                    <div>
                        <span class="grant-email">${escapeHtml(g.user_email)}</span>
                        <span class="role-pill role-admin" style="margin-left: 6px;">${escapeHtml(g.permission)}</span>
                    </div>
                    <button class="btn-xs btn-danger btn-quick-revoke" data-user-id="${g.user_id}" data-doc-id="${g.document_id}">
                        Revoke
                    </button>
                `;
                elements.grantsList.appendChild(li);
            });

            elements.grantsList.querySelectorAll('.btn-quick-revoke').forEach(btn => {
                btn.addEventListener('click', () => {
                    executePermissionAction('revoke', btn.dataset.docId, btn.dataset.userId);
                });
            });
        } catch (err) {
            elements.grantsPlaceholder.textContent = 'Error loading grants.';
        }
    }

    async function executePermissionAction(action, documentId, targetUserId, permission = 'READ') {
        if (!state.token) {
            showToast('Authentication required', 'error');
            return;
        }

        const endpoint = action === 'grant' ? '/api/permissions/grant' : '/api/permissions/revoke';
        const payload = { documentId, targetUserId };
        if (action === 'grant') payload.permission = permission;

        elements.permissionFeedback.style.display = 'block';
        elements.permissionFeedback.className = 'feedback-banner feedback-success';
        elements.permissionFeedback.textContent = `Executing real-time database ${action.toUpperCase()}...`;

        try {
            const res = await fetch(endpoint, {
                method: 'POST',
                headers: {
                    'Content-Type': 'application/json',
                    Authorization: `Bearer ${state.token}`,
                },
                body: JSON.stringify(payload),
            });

            const data = await res.json();
            if (res.ok) {
                elements.permissionFeedback.className = 'feedback-banner feedback-success';
                elements.permissionFeedback.innerHTML = `
                    <strong>✓ Action Succeeded:</strong> ${escapeHtml(data.message)}.<br>
                    ${action === 'revoke' ? '<small>Immediate 404 cutoff enforced: Target user requests will now receive 404 Not Found without delay.</small>' : '<small>Real-time delegation updated: Target user can now download the document.</small>'}
                `;
                showToast(`Permission ${action.toUpperCase()} successful`, 'success');
                loadGrantsForDocument(documentId);
                loadDocuments();
                refreshAuditLedger();
            } else {
                elements.permissionFeedback.className = 'feedback-banner feedback-error';
                elements.permissionFeedback.innerHTML = `
                    <strong>✗ Error (${res.status}):</strong> ${escapeHtml(data.error || 'Action failed')}
                `;
                showToast(`Permission ${action} failed`, 'error');
                refreshAuditLedger();
            }
        } catch (err) {
            elements.permissionFeedback.className = 'feedback-banner feedback-error';
            elements.permissionFeedback.textContent = 'Network error while executing permission action.';
        }
    }

    // ==========================================================================
    // Cryptographic Audit Ledger Inspector
    // ==========================================================================
    async function refreshAuditLedger() {
        if (!state.token) return;
        // Verify ledger if user is ADMIN
        if (state.user?.role === 'ADMIN') {
            await verifyAuditLedger(false);
        }
    }

    async function verifyAuditLedger(isManualClick = true) {
        if (!state.token) {
            showToast('Authentication required', 'error');
            return;
        }

        if (state.user?.role !== 'ADMIN') {
            elements.ledgerStatusBanner.className = 'ledger-status-banner status-pending';
            elements.ledgerBadgeChip.textContent = 'RESTRICTED';
            elements.ledgerBadgeChip.className = 'status-badge-chip role-none';
            elements.ledgerHeadline.textContent = 'Cryptographic verification requires ADMIN role (404 Concealment active for non-admins)';
            elements.chainExplorer.innerHTML = `
                <div class="text-center text-muted" style="padding: 2rem;">
                    To recalculate the SHA-256 hash chain and inspect the immutable audit ledger, click the <strong>ADMIN</strong> fast-switcher button in the Identity Matrix above.
                </div>
            `;
            if (isManualClick) {
                showToast('Admin role required for audit ledger inspection', 'info');
            }
            return;
        }

        elements.btnVerifyLedger.disabled = true;
        elements.btnVerifyLedger.innerHTML = `
            <svg class="spinning" viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><circle cx="12" cy="12" r="10"/><path d="M12 6v6l4 2"/></svg>
            Verifying Chain...
        `;

        try {
            const res = await fetch('/api/audit/verify', {
                headers: { Authorization: `Bearer ${state.token}` },
            });

            if (!res.ok) {
                elements.ledgerStatusBanner.className = 'ledger-status-banner status-tampered';
                elements.ledgerBadgeChip.textContent = 'DENIED';
                elements.ledgerHeadline.textContent = 'Ledger endpoint returned error status';
                return;
            }

            const data = await res.json();
            const isValid = data.status === 'INTACT';
            const chain = data.chain || data.details?.chain || [];

            elements.ledgerStatusBanner.className = isValid
                ? 'ledger-status-banner status-intact'
                : 'ledger-status-banner status-tampered';

            elements.ledgerBadgeChip.textContent = data.status;
            elements.ledgerHeadline.textContent = isValid
                ? 'Cryptographic Ledger Verified: All SHA-256 Hashes INTACT'
                : `TAMPERING DETECTED: Chain broken at block ID ${data.details?.brokenAtId || 'Unknown'}`;

            elements.ledgerTotalBlocks.textContent = `Blocks: ${chain.length}`;
            elements.ledgerVerifiedAt.textContent = `Last Verified: ${new Date().toLocaleTimeString()}`;

            renderChainExplorer(chain, isValid, data.details?.brokenAtId);

            if (isManualClick) {
                showToast(`Ledger Integrity: ${data.status} (${chain.length} blocks verified)`, isValid ? 'success' : 'error');
            }
        } catch (err) {
            elements.ledgerStatusBanner.className = 'ledger-status-banner status-tampered';
            elements.ledgerHeadline.textContent = 'Verification request failed';
        } finally {
            elements.btnVerifyLedger.disabled = false;
            elements.btnVerifyLedger.innerHTML = `
                <svg viewBox="0 0 24 24" width="16" height="16" fill="none" stroke="currentColor" stroke-width="2"><path d="M22 11.08V12a10 10 0 1 1-5.93-9.14"/><polyline points="22 4 12 14.01 9 11.01"/></svg>
                Verify Ledger Integrity
            `;
        }
    }

    function renderChainExplorer(chain, isValid, brokenId) {
        if (!chain || chain.length === 0) {
            elements.chainExplorer.innerHTML = '<div class="text-center text-muted" style="padding: 2rem;">No audit blocks recorded yet.</div>';
            return;
        }

        elements.chainExplorer.innerHTML = '';
        // Render in reverse chronological order (newest first) for best usability
        const reversedChain = [...chain].reverse();

        reversedChain.forEach((block, idx) => {
            const blockNum = chain.length - idx;
            const isBroken = block.id === brokenId;
            const blockEl = document.createElement('div');
            blockEl.className = `chain-block ${isBroken ? 'block-tampered' : ''}`;

            const timeStr = new Date(block.timestamp).toLocaleString();
            const prevHashShort = block.previous_hash.slice(0, 14) + '...' + block.previous_hash.slice(-10);
            const currHashShort = block.current_hash.slice(0, 14) + '...' + block.current_hash.slice(-10);

            blockEl.innerHTML = `
                <div class="chain-block-header">
                    <div>
                        <span class="block-index">#${blockNum} Block</span>
                        <span class="action-badge action-${block.action}">${escapeHtml(block.action)}</span>
                        <span class="role-pill ${block.status === 'SUCCESS' ? 'role-admin' : 'role-viewer'}" style="margin-left: 4px;">${escapeHtml(block.status)}</span>
                    </div>
                    <span class="text-xs text-muted">${timeStr}</span>
                </div>
                <div class="block-meta-grid">
                    <div class="block-meta-item">
                        <span class="block-meta-label">Actor:</span>
                        <span class="block-meta-val">${block.actor_id ? block.actor_id.slice(0, 8) + '...' : 'ANON'}</span>
                    </div>
                    <div class="block-meta-item">
                        <span class="block-meta-label">Target Doc:</span>
                        <span class="block-meta-val">${block.target_document_id ? block.target_document_id.slice(0, 8) + '...' : 'NONE'}</span>
                    </div>
                </div>
                <div class="hash-chain-visual">
                    <div class="hash-row">
                        <span class="hash-label">Prev Hash:</span>
                        <span class="hash-val" title="${escapeHtml(block.previous_hash)}">${prevHashShort}</span>
                    </div>
                    <div class="hash-row">
                        <span class="hash-label">Current:</span>
                        <span class="hash-val hash-val-current" title="${escapeHtml(block.current_hash)}">${currHashShort}</span>
                    </div>
                </div>
            `;
            elements.chainExplorer.appendChild(blockEl);
        });
    }

    // ==========================================================================
    // Event Listeners & Setup
    // ==========================================================================
    function setupEventListeners() {
        // Persona Fast Switchers
        elements.btnSwitchAdmin.addEventListener('click', () => {
            login(elements.btnSwitchAdmin.dataset.email, elements.btnSwitchAdmin.dataset.pass);
        });
        elements.btnSwitchOwner.addEventListener('click', () => {
            login(elements.btnSwitchOwner.dataset.email, elements.btnSwitchOwner.dataset.pass);
        });
        elements.btnSwitchViewer.addEventListener('click', () => {
            login(elements.btnSwitchViewer.dataset.email, elements.btnSwitchViewer.dataset.pass);
        });

        // Logout
        elements.btnLogout.addEventListener('click', () => {
            setSession(null, null);
            showToast('Session cleared', 'info');
        });

        // Copy buttons
        elements.btnCopyToken.addEventListener('click', () => {
            if (state.token) {
                navigator.clipboard.writeText(state.token);
                showToast('JWT copied to clipboard', 'info');
            }
        });
        elements.btnCopyUserId.addEventListener('click', () => {
            if (state.user?.id) {
                navigator.clipboard.writeText(state.user.id);
                showToast('User UUID copied', 'info');
            }
        });

        // Manual Login Form
        elements.formManualLogin.addEventListener('submit', (e) => {
            e.preventDefault();
            login(elements.inputLoginEmail.value.trim(), elements.inputLoginPassword.value);
        });

        // File Drag & Drop Handling
        elements.dropZone.addEventListener('dragover', (e) => {
            e.preventDefault();
            elements.dropZone.classList.add('dragover');
        });
        elements.dropZone.addEventListener('dragleave', () => {
            elements.dropZone.classList.remove('dragover');
        });
        elements.dropZone.addEventListener('drop', (e) => {
            e.preventDefault();
            elements.dropZone.classList.remove('dragover');
            if (e.dataTransfer.files.length > 0) {
                handleFileSelection(e.dataTransfer.files[0]);
            }
        });

        elements.inputFile.addEventListener('change', () => {
            if (elements.inputFile.files.length > 0) {
                handleFileSelection(elements.inputFile.files[0]);
            }
        });

        function handleFileSelection(file) {
            elements.selectedFileName.style.display = 'inline-block';
            elements.selectedFileName.textContent = `${file.name} (${(file.size / 1024).toFixed(1)} KB)`;
            elements.dropZoneTitle.textContent = `Selected: ${file.name}`;
        }

        // Upload Form Submit
        elements.formUpload.addEventListener('submit', (e) => {
            e.preventDefault();
            const file = elements.inputFile.files[0];
            if (!file) {
                showToast('Please select a file to upload', 'error');
                return;
            }
            uploadFile(file, elements.selectCategory.value);
        });

        // Adversarial Demo: Genuine PDF Upload
        elements.btnTestRealPdf.addEventListener('click', () => {
            const genuineContent = '%PDF-1.4\n%Genuine Test PDF Document for TrustVault\n1 0 obj\n<< /Title (Confidential Audit) >>\nendobj\n%%EOF';
            const blob = new Blob([genuineContent], { type: 'application/pdf' });
            const file = new File([blob], 'genuine_security_audit.pdf', { type: 'application/pdf' });
            uploadFile(file, 'confidential');
        });

        // Adversarial Demo: Spoofed Executable (MZ Header)
        elements.btnTestFakePdf.addEventListener('click', () => {
            const fakeExecutableContent = 'MZ_DISGUISED_EXECUTABLE_PAYLOAD_TESTING_MAGIC_BYTE_REJECTION';
            const blob = new Blob([fakeExecutableContent], { type: 'application/pdf' });
            const file = new File([blob], 'malicious_executable_disguised.pdf', { type: 'application/pdf' });
            uploadFile(file, 'legal');
        });

        // Refresh Documents
        elements.btnRefreshDocs.addEventListener('click', loadDocuments);

        // Permission Quick Selects
        elements.btnSelectLatestDoc.addEventListener('click', () => {
            if (state.documentsList.length > 0) {
                selectDocumentForPermission(state.documentsList[0].id);
            } else {
                showToast('No documents available in vault to select', 'info');
            }
        });

        elements.btnSelectViewerId.addEventListener('click', () => {
            const viewer = state.usersList.find(u => u.role === 'VIEWER');
            if (viewer) {
                elements.inputTargetUserId.value = viewer.id;
                showToast(`Filled Viewer ID: ${viewer.id}`, 'info');
            } else {
                showToast('Viewer user ID not found', 'error');
            }
        });

        // Grant & Revoke Actions
        elements.btnGrantPerm.addEventListener('click', () => {
            const docId = elements.inputTargetDocId.value.trim();
            const userId = elements.inputTargetUserId.value.trim();
            const perm = elements.selectPermissionType.value;
            if (!docId || !userId) {
                showToast('Please enter both Document ID and Target User ID', 'error');
                return;
            }
            executePermissionAction('grant', docId, userId, perm);
        });

        elements.btnRevokePerm.addEventListener('click', () => {
            const docId = elements.inputTargetDocId.value.trim();
            const userId = elements.inputTargetUserId.value.trim();
            if (!docId || !userId) {
                showToast('Please enter both Document ID and Target User ID', 'error');
                return;
            }
            executePermissionAction('revoke', docId, userId);
        });

        elements.btnRefreshGrants.addEventListener('click', () => {
            const docId = elements.inputTargetDocId.value.trim();
            if (docId) loadGrantsForDocument(docId);
            else showToast('Enter a Document ID to check grants', 'info');
        });

        // Audit Ledger Verification
        elements.btnVerifyLedger.addEventListener('click', () => {
            verifyAuditLedger(true);
        });
    }

    function refreshAllData() {
        fetchUsers();
        loadDocuments();
        refreshAuditLedger();
    }

    function escapeHtml(str) {
        if (!str) return '';
        return String(str)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    // ==========================================================================
    // Initialization
    // ==========================================================================
    async function init() {
        setupEventListeners();
        await fetchUsers();

        // If no token stored, auto-login as OWNER or ADMIN for immediate interactive experience
        if (!state.token) {
            await login('admin@trustvault.local', 'AdminPass123!');
        } else {
            updateSessionUI();
            refreshAllData();
        }
    }

    init();
})();
