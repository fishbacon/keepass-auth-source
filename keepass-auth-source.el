;;; keepass-auth-source.el --- auth-source for KeePass -*- lexical-binding: t -*-

;; Author: Mark Faldborg
;; Maintainer: Mark Faldborg
;; Version: 1.0.3
;; Package-Requires: (dash s)
;; Homepage: https://github.com/fishbacon/keepass-auth-source
;; Keywords: keepass auth-source passwords


;; This file is not part of GNU Emacs

;; This program is free software: you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <https://www.gnu.org/licenses/>.


;;; Commentary:

;; Adds KeePass support to auth-source.

;;; Code:
(require 'auth-source)
(require 'cl-lib)
(require 'password-cache)
(require 'simple)
(require 'dash)
(require 's)

;;;###autoload
(defcustom keepass-auth-source-cache-expiry 7200
  "How many seconds the KeePass database password is cached.
Set to nil to disable expiry."
  :type '(choice (const :tag "Never" nil)
          (const :tag "All Day" 86400)
          (const :tag "2 Hours" 7200)
          (const :tag "30 Minutes" 1800)
          (integer :tag "Seconds")))

(defcustom keepass-auth-match-title t
  "Whether to use title argument for selecting auth entries.
Entries matching `title' will be selected if one and only one entry
matches on `url'.  If no entries match but multiple are found the user
is prompted to select the auth.")

;;;###autoload
(defcustom keepass-auth-source-async nil
  "Whether to use asynchronous process execution for KPScript.
When non-nil, KPScript is invoked using `make-process' instead of
synchronous `call-process'.  This can improve responsiveness when
accessing KeePass databases over slow network connections."
  :type 'boolean
  :group 'auth-source)

(defun keepass-auth-source--parse-auth (auth-string port)
  "Parse a single auth entry from AUTH-STRING for PORT."
  (save-match-data
    (with-temp-buffer
      (insert auth-string)
      (goto-char (point-min))
      (let ((result `(:port ,port))
            (mappings '(:url :host
                        :username :user
                        :password :secret)))
        (while (search-forward-regexp "^S: \\(.*\\) = \\(.*\\)$" nil t)
          (let* ((key (intern (concat ":" (downcase (match-string 1)))))
                 (key (or (plist-get mappings key) key))
                 (value (match-string 2))
                 (value (if (eq :secret key) `(lambda () ,value) value)))
            (setq result (plist-put result key value))))
        result))))

(defun keepass-auth-source--parse (output port)
  "Parse KPScript OUTPUT for PORT and return auths and status."
  (let* ((results (s-split "\n\n" output))
         (status (-first-item results))
         (auths (--map (keepass-auth-source--parse-auth it port) (-drop-last 1 results))))
    `(,auths ,status)))

(defun keepass-auth-source--process-results (results status entity max result-for-title)
  "Process KPScript results and handle errors or return credentials.
RESULTS is the parsed credential list, STATUS is the KPScript status output,
ENTITY is the database file path, MAX is the maximum results to return,
RESULT-FOR-TITLE is title-filtered results."
  (let ((result (if (= 1 (length result-for-title)) result-for-title results)))
    (with-temp-buffer
      (insert status)
      (goto-char 0)
      (cond
        ((search-forward-regexp "^Unhandled Exception:" nil t)
         (progn
           (password-cache-remove entity)
           (user-error
            "An exception was thrown by KeePass.exe (your KPScript is likely out of date)\n %s"
            status)))
        ((search-forward-regexp "^E:" nil t)
         (cond
           ((search-forward-regexp "The master key is invalid" nil t)
            (progn
              (password-cache-remove entity)
              (user-error "Incorrect password for %s" entity)))
           (t (user-error "Something went wrong in keepass: %s"
                          status))))
        ((= 0 (length result)) nil)
        ((and (= max 1) (> (length result) max))
         (let* ((completions (--map (cons
                                     (format "%s (%s)" (plist-get it :user) (plist-get it :title))
                                     it)
                                    result)))
           (list (cdr (assoc-string
                       (completing-read "Multiple passwords in keepass db pick one: "
                                        completions
                                        nil t)
                       completions)))))
        (t (-take max result))))))

(defun keepass-auth-source--async-process-filter (process output)
  "Process filter for async KPScript execution.
Accumulates OUTPUT from PROCESS in the process's output buffer."
  (when (buffer-live-p (process-buffer process))
    (with-current-buffer (process-buffer process)
      (goto-char (point-max))
      (insert output))))

(defun keepass-auth-source--async-process-sentinel (process event callback spec)
  "Process sentinel for async KPScript execution.
Handles process completion, parses results, and invokes CALLBACK with
credentials.
PROCESS is the KPScript process, EVENT describes the process event,
CALLBACK is the auth-source callback function, SPEC contains search parameters."
  (when (memq (process-status process) '(exit signal))
    (let* ((exit-status (process-exit-status process))
           (output (with-current-buffer (process-buffer process)
                     (buffer-string)))
           (port (plist-get spec :port))
           (entity (plist-get spec :entity))
           (max (or (plist-get spec :max) 1))
           (title (plist-get spec :title)))
      (kill-buffer (process-buffer process))
      (condition-case err
          (if (= exit-status 0)
              (let* ((parsed (keepass-auth-source--parse output port))
                     (results (car parsed))
                     (status (car (last parsed)))
                     (result-for-title (when (and keepass-auth-match-title (not (s-blank-p title)))
                                         (--filter (s-contains-p title (plist-get it :title) t) results)))
                     (final-result (keepass-auth-source--process-results results status entity max result-for-title)))
                (when callback
                  (funcall callback final-result)))
            (when callback
              (funcall callback nil)))
        (error
         (when callback
           (funcall callback nil))
         (signal (car err) (cdr err)))))))

(defun keepass-auth-source--execute-sync (keepass-command port entity max title)
  "Execute KPScript synchronously and return processed results.
KEEPASS-COMMAND is the command to execute, PORT is the target port,
ENTITY is the database file, MAX is max results, TITLE is for filtering."
  (let* ((output (shell-command-to-string keepass-command))
         (parsed (keepass-auth-source--parse output port))
         (results (car parsed))
         (status (car (last parsed)))
         (result-for-title (when (and keepass-auth-match-title (not (s-blank-p title)))
                             (--filter (s-contains-p title (plist-get it :title) t) results))))
    (keepass-auth-source--process-results results status entity max result-for-title)))

(defun keepass-auth-source--execute-async (keepass-command port entity max title callback)
  "Execute KPScript asynchronously and invoke CALLBACK with results.
KEEPASS-COMMAND is the command to execute, PORT is the target port,
ENTITY is the database file, MAX is max results, TITLE is for filtering,
CALLBACK is invoked with the results when complete."
  (let* ((command-parts (split-string keepass-command))
         (program (car command-parts))
         (args (cdr command-parts))
         (buffer (generate-new-buffer " *keepass-auth-source*"))
         (spec (list :port port :entity entity :max max :title title))
         (process (make-process
                   :name "keepass-auth-source"
                   :buffer buffer
                   :command (cons program args)
                   :filter #'keepass-auth-source--async-process-filter
                   :sentinel (lambda (proc event)
                               (keepass-auth-source--async-process-sentinel proc event callback spec)))))
    process))

(cl-defun keepass-auth-source-search (&rest spec
                                      &key backend type host user port max title
                                        &allow-other-keys)
  "Find password for a request.
If several passwords are available prompt user to select an entry.
When `keepass-auth-source-async' is non-nil, this function returns immediately
and the results are provided asynchronously via callback.

SPEC contains search parameters including BACKEND, TYPE, HOST, USER,
PORT, MAX, and TITLE."
  (let ((entity (slot-value backend 'source)))
    (when (file-exists-p entity)
      (let* ((url (url-generic-parse-url host))
             (url (if (url-fullness url)
                      url
                    (url-generic-parse-url (concat "//" host))))
             (host (or (url-host url) ""))
             (max (or max 1))
             (path-name (or (url-filename url) ""))
             (password-prompt (format "Keepass password (%s): " entity))
             (password (let ((password-cache-expiry keepass-auth-source-cache-expiry)
                             (password
                              (cond
                                ((password-read-from-cache entity))
                                ((password-read password-prompt entity)))))
                         (password-cache-add entity password)
                         password))
             (keepass-command-base (s-join " "
                                           '("kpscript -C:ListEntries"
                                             "${db}"
                                             "-ref-Username:${user}"
                                             "-ref-URL://${url}//"
                                             "-pw:${password}")))
             (keepass-command-fields `((db . ,(expand-file-name entity))
                                       (user . ,(or user ""))
                                       (url . ,(concat host path-name))
                                       (password . ,password)))
             (keepass-command (s-format keepass-command-base 'aget keepass-command-fields)))
        
        (if keepass-auth-source-async
            ;; Async mode - extract callback from spec if available
            (let ((callback (plist-get spec :callback)))
              (keepass-auth-source--execute-async keepass-command port entity max title callback)
              ;; Return immediately for async operation
              nil)
          ;; Sync mode - existing behavior
          (keepass-auth-source--execute-sync keepass-command port entity max title))))))

(defun keepass-auth-source-backend-parser (entry)
  "Provide keepass backend for files with the .kdbx extension.
ENTRY is the file path to check for .kdbx extension."
  (when (and (stringp entry)
             (string-equal "kdbx" (file-name-extension entry)))
    (auth-source-backend :type 'keepass
                         :source entry
                         :search-function #'keepass-auth-source-search)))
;;;###autoload
(defun keepass-auth-source-enable ()
  "Enable keepass auth source.
Executables for keepass and kpscript must be available on the path for this to work."
  (interactive)
  (if (-all-p #'executable-find '("keepass" "kpscript"))
      (progn
        (auth-source-forget-all-cached)
        (if (boundp 'auth-source-backend-parser-functions)
            (add-hook 'auth-source-backend-parser-functions #'keepass-auth-source-backend-parser)
          (advice-add 'auth-source-backend-parse :before-until #'keepass-auth-source-backend-parser)))
    (error "Executables for keepass or kpscript missing")))

(provide 'keepass-auth-source)
;;; keepass-auth-source.el ends here
