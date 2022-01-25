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
  "How many seconds the KeePass database password is cached,
or nil to disable expiry."
  :type '(choice (const :tag "Never" nil)
          (const :tag "All Day" 86400)
          (const :tag "2 Hours" 7200)
          (const :tag "30 Minutes" 1800)
          (integer :tag "Seconds")))

(defcustom keepass-auth-match-title t
  "If `title' argument passed to `auth-source-search' should be used in selecting an entry.
Entries matching `title' will be selected if one and only one entry matches on `url'.
If no entries match but multiple are found the user is prompted to select the auth.")

(defun keepass-auth-source--parse-auth (auth-string port)
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
  (let* ((results (s-split "\n\n" output))
         (status (-first-item results))
         (auths (--map (keepass-auth-source--parse-auth it port) (-drop-last 1 results))))
    `(,auths ,status)))

(cl-defun keepass-auth-source-search (&rest spec
                                      &key backend type host user port max title
                                        &allow-other-keys)
  "Find password for a request, if several passwords are available prompt user to select an entry."
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
             (keepass-command (s-format keepass-command-base 'aget keepass-command-fields))
             (output (shell-command-to-string keepass-command))
             (result (keepass-auth-source--parse output port))
             (status (-last-item result))
             (result (-first-item result))
             (result-for-title (when (and keepass-auth-match-title (not (s-blank-p title)))
                                 (--filter (s-contains-p title (plist-get it :title) t) result)))
             (result (if (= 1 (length result-for-title)) result-for-title result)))
        (cond
          ((s-prefix-p "E:" status)
           (cond
             ((s-contains-p "E: The master key" status)
              (progn
                (password-cache-remove entity)
                (user-error "Incorrect password for %s" entity)))
             (t (user-error "Something went wrong in keepass: %s" status))))
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
          (t (-take max result)))))))

(defun keepass-auth-source-backend-parser (entry)
  "Provides keepass backend for files with the .kdbx extension."
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
    (error "Executables for keepass or kpscript missing.")))

(provide 'keepass-auth-source)
;;; keepass-auth-source.el ends here
