ifdef FD_HAS_HOSTED
STL_TEST_LIBS:=fd_stl fd_util fd_ballet

# fd_stl unit tests
# $(call make-unit-test,test_stl_all,      test_stl_all,      $(STL_TEST_LIBS))
# $(call run-unit-test,test_stl_all)

$(call make-unit-test,test_stl_client_server, test_stl_client_server, $(STL_TEST_LIBS))
$(call run-unit-test,test_stl_client_server)

$(call make-unit-test,test_stl_live, test_stl_live, $(STL_TEST_LIBS))
$(call run-unit-test,test_stl_live)


endif
