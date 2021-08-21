;;; keepass-auth-source-search.el --- auth-source for KeePass -*- lexical-binding: t -*-

;; Author: Mark Faldborg
;; Maintainer: Mark Faldborg
;; Version: 1.0.0
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
(require 'dash)
(require 's)

(cl-defun keepass-auth-source-search (&rest spec
                                      &key backend type host user port max
                                        &allow-other-keys)
  "Find password for a request, if several passwords are available prompt user to select an entry."
  (let ((entity (slot-value backend 'source)))
    (when (file-exists-p entity)
      (let* ((url (url-generic-parse-url host))
             (host (url-host url))
             (max (or max 1))
             (path-name (url-filename url))
             (password-prompt (format "Keepass password (%s): " entity))
             (password (let ((password
                              (cond
                                ((password-read-from-cache entity))
                                ((password-read password-prompt entity)))))
                         (password-cache-add entity password)
                         password))
             (keepass-command-base (s-join " "
                                      (list "kpscript -C:GetEntryString"
                                            "${db}"
                                            "-field:${field}"
                                            "-ref-Username:${user}"
                                            "-ref-URL://${url}//"
                                            "-pw:${password}")))
             (keepass-command-fields (list (cons 'db (expand-file-name entity))
                                      (cons 'field "Password")
                                      (cons 'user user)
                                      (cons 'url (concat host path-name))
                                      (cons 'password password)))
             (keepass-command (s-format keepass-command-base 'aget keepass-command-fields))
             (keepass-command-title (s-format keepass-command-base 'aget
                                         (cons '(field . "Title") keepass-command-fields)))
             (result-s (shell-command-to-string keepass-command))
             (result (-drop-last 2 (s-split "\n" result-s)))
             (is-error (not (s-contains-p "OK: " result-s))))
        (cond
          (is-error
           (cond
             ((s-contains-p "E: The master key" result-s)
              (progn
                (password-cache-remove entity)
                (error "Incorrect password for %s" entity)))
             (t (error "Something went wrong in keepass: %s" result-s))))
          ((= 0 (length result)) nil)
          ((= max 1)
           (let* ((titles (s-split "\n" (shell-command-to-string keepass-command-title)))
                  (completions (-zip-pair (-drop-last 2 titles) result)))
             (cdr (assoc-string (completing-read "Multiple entries in db pick one: "
                                                 completions
                                                 nil t)
                                completions))))
          (t (seq-take max result)))))))

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

(provide 'keepass-auth-source-search)
;;; keepass-auth-source-search.el ends here
