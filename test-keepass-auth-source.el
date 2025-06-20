;;; test-keepass-auth-source.el --- Tests for keepass-auth-source -*- lexical-binding: t -*-

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

;; Tests for keepass-auth-source async functionality.

;;; Code:

(require 'ert)

;; Mock dependencies for testing without actual packages
(defun keepass-auth-source--mock-dash ()
  "Mock dash functions for testing."
  (fset '-all-p (lambda (predicate list)
                  (cl-every predicate list)))
  (fset '--map (lambda (form list)
                 (mapcar (lambda (it) (eval form `((it . ,it)))) list)))
  (fset '--filter (lambda (form list)
                    (cl-remove-if-not (lambda (it) (eval form `((it . ,it)))) list)))
  (fset '-first-item (lambda (list) (car list)))
  (fset '-drop-last (lambda (n list) (butlast list n)))
  (fset '-take (lambda (n list) (cl-subseq list 0 (min n (length list))))))

(defun keepass-auth-source--mock-s ()
  "Mock s functions for testing."
  (fset 's-join (lambda (separator strings) (mapconcat 'identity strings separator)))
  (fset 's-split (lambda (separator string) (split-string string separator)))
  (fset 's-format (lambda (template replacer) 
                    (replace-regexp-in-string
                     "${\\([^}]+\\)}"
                     (lambda (match)
                       (let ((key (intern (match-string 1 match))))
                         (funcall replacer key)))
                     template)))
  (fset 's-contains-p (lambda (needle haystack &optional ignore-case)
                        (if ignore-case
                            (string-match-p (regexp-quote needle) haystack)
                          (string-match-p (regexp-quote needle) haystack))))
  (fset 's-blank-p (lambda (s) (or (null s) (string= s "")))))

(defun keepass-auth-source--setup-test-env ()
  "Set up test environment with mocked dependencies."
  (keepass-auth-source--mock-dash)
  (keepass-auth-source--mock-s)
  ;; Mock aget function
  (fset 'aget (lambda (key) (cdr (assoc key '((db . "/test.kdbx")
                                              (user . "testuser")
                                              (url . "example.com")
                                              (password . "testpass")))))))

;; Load the source file with mocked dependencies
(keepass-auth-source--setup-test-env)

;; Load main source after setting up mocks
(load-file "keepass-auth-source.el")

;; Mock additional dependencies
(defvar keepass-auth-source-cache-expiry 7200)
(defvar keepass-auth-match-title t)
(defvar keepass-auth-source-async nil)

(defun keepass-auth-source--parse-auth (auth-string port)
  "Mock parse auth function for testing."
  `(:user "testuser" :secret (lambda () "testpass") :host "example.com" :port ,port))

(defun keepass-auth-source--parse (output port)
  "Mock parse function for testing."
  (if (string-match-p "^OK:" output)
      `(((:user "testuser" :secret (lambda () "testpass") :host "example.com" :port ,port))
        "OK: Operation completed successfully")
    `(() "E: Error occurred")))

(defun keepass-auth-source--process-results (results status entity max result-for-title)
  "Mock process results function for testing."
  (cond
    ((string-match-p "^E:" status) (error "Mock error"))
    ((= 0 (length results)) nil)
    (t results)))

(ert-deftest test-keepass-auth-source-async-variable ()
  "Test that the async variable is properly defined."
  (should (boundp 'keepass-auth-source-async))
  (should (eq keepass-auth-source-async nil))) ; default should be nil

(ert-deftest test-keepass-auth-source-async-process-filter ()
  "Test async process filter accumulates output."
  (with-temp-buffer
    (let ((process (make-process :name "test" :buffer (current-buffer) :command '("echo" "test"))))
      (keepass-auth-source--async-process-filter process "test output")
      (should (string= (buffer-string) "test output"))
      (delete-process process))))

(ert-deftest test-keepass-auth-source-sync-execution ()
  "Test synchronous execution path."
  (let ((keepass-auth-source-async nil))
    (cl-letf (((symbol-function 'shell-command-to-string)
               (lambda (cmd) "OK: test output\n\nS: Username = testuser\nS: Password = testpass\n\n"))
              ((symbol-function 'keepass-auth-source--process-results)
               (lambda (results status entity max result-for-title)
                 (list (car results)))))
      (let ((result (keepass-auth-source--execute-sync "test-command" 80 "/test.kdbx" 1 "")))
        (should (listp result))
        (should (= (length result) 1))))))

(ert-deftest test-keepass-auth-source-async-execution ()
  "Test asynchronous execution path returns process."
  (let ((keepass-auth-source-async t))
    (cl-letf (((symbol-function 'make-process)
               (lambda (&rest args) 'mock-process)))
      (let ((result (keepass-auth-source--execute-async "kpscript test" 80 "/test.kdbx" 1 "" nil)))
        (should (eq result 'mock-process))))))

(provide 'test-keepass-auth-source)
;;; test-keepass-auth-source.el ends here